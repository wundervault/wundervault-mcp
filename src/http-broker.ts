/**
 * Perform one typed operation with a held credential.
 *
 * The caller never supplies a URL, headers or a body — only typed arguments against a
 * signed definition. Everything about where the request goes comes from the definition,
 * which the server cannot author (see opdef.ts).
 *
 * The hard parts here are all about a request going somewhere other than where the
 * definition says: DNS resolving to a private address, a second lookup between check and
 * connect, a redirect carrying the credential off-origin, or a header the caller slipped
 * in. Each is handled explicitly rather than by trusting the HTTP client's defaults.
 */
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import { isIP } from 'node:net';
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib';
import type { OperationDefinition, CredentialBinding } from './opdef.js';
import { filterResponse } from './opdef.js';
import { renderCredential, secretForms, pathBindingProblem, pathWithKey } from './delivery.js';
import { VERSION } from './version.js';

export interface CallResult {
  ok: boolean;
  status?: number;
  body?: unknown;
  error?: string;
  /** Set when the upstream redirected. The redirect is NOT followed. */
  redirectedTo?: string;
}

/**
 * Remove the credential from anything on its way back to the caller.
 *
 * The field allowlist is not sufficient by itself: an upstream can echo the credential
 * in a field the operation legitimately allows. This is exact-match scrubbing, so it is
 * defence in depth and NOT a guarantee — an upstream that encodes the value still
 * defeats it, which is why the tool no longer claims non-disclosure outright.
 */
export function scrubSecret(value: unknown, secret: string): unknown {
  if (!secret) return value;
  if (typeof value === 'string') return value.split(secret).join('[REDACTED]');
  if (Array.isArray(value)) return value.map((v) => scrubSecret(v, secret));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // Keys too. An upstream returning {"content":{"sk-live":"echo"}} put the secret in
      // the KEY, and scrubbing only values left it in the stringified output.
      out[k.split(secret).join('[REDACTED]')] = scrubSecret(v, secret);
    }
    return out;
  }
  return value;
}

const DEFAULT_RESPONSE_BYTES = 8 * 1024 * 1024;
const DEFAULT_REQUEST_BYTES = 1024 * 1024;
const CONNECT_TIMEOUT_MS = 10_000;
const DNS_TIMEOUT_MS = 5_000;
const TOTAL_TIMEOUT_MS = 60_000;

/**
 * Address ranges a brokered request must never reach.
 *
 * The point is not tidiness: cloud metadata at 169.254.169.254 hands out instance
 * credentials, and loopback reaches whatever else is running on this machine. A hostname
 * the definition names could resolve to any of these, whether by misconfiguration or by
 * an attacker controlling the DNS record.
 */
function isBlockedIPv4(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0) return true;                                  // "this network"
  if (a === 10) return true;                                 // RFC1918
  if (a === 127) return true;                                // loopback
  if (a === 100 && b >= 64 && b <= 127) return true;         // CGNAT
  if (a === 169 && b === 254) return true;                   // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;          // RFC1918
  if (a === 192 && b === 168) return true;                   // RFC1918
  if (a === 192 && b === 0) return true;                     // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true;       // benchmarking
  if (a === 198 && b === 51) return true;                    // TEST-NET-2
  if (a === 203 && b === 0) return true;                     // TEST-NET-3
  if (a >= 224) return true;                                 // multicast + reserved
  return false;
}

/** Expand any IPv6 spelling to eight 16-bit groups, or null if it is not one. */
export function expandIPv6(ip: string): number[] | null {
  let s = ip;
  // A trailing dotted-quad (::ffff:127.0.0.1) becomes two hex groups first.
  const dotted = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (dotted) {
    const p = dotted[2].split('.').map(Number);
    if (p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    s = dotted[1] + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  const out = groups.map((g) => (g === '' ? 0 : parseInt(g, 16)));
  if (out.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return out;
}

export function isBlockedAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return isBlockedIPv4(ip);
  if (v !== 6) return true;                                  // not an address at all

  // Decide on the EXPANDED groups, never on the string. Textual checks kept missing
  // spellings: first the fully-expanded IPv4-mapped form, then 0:0:0:0:0:0:0:1, which
  // is loopback written the long way and which a `=== "::1"` comparison waves through.
  const g = expandIPv6(ip.toLowerCase());
  if (!g) return true;                                       // unparseable: refuse

  const allZeroTop5 = g.slice(0, 5).every((x) => x === 0);

  // ::ffff:a.b.c.d — a v4 address wearing v6 notation. Apply the v4 rules to it.
  if (allZeroTop5 && g[5] === 0xffff) {
    return isBlockedIPv4([g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.'));
  }

  // :: (unspecified) and ::1 (loopback), in any spelling.
  if (allZeroTop5 && g[5] === 0 && g[6] === 0 && g[7] <= 1) return true;

  // ::a.b.c.d — deprecated IPv4-compatible form, still routes to a v4 destination.
  if (allZeroTop5 && g[5] === 0 && !(g[6] === 0 && g[7] === 0)) {
    return isBlockedIPv4([g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.'));
  }

  const top = g[0];
  if ((top & 0xfe00) === 0xfc00) return true;                // fc00::/7  unique local
  if ((top & 0xffc0) === 0xfe80) return true;                // fe80::/10 link-local
  if ((top & 0xff00) === 0xff00) return true;                // ff00::/8  multicast
  return false;
}

/**
 * The lookup shim handed to the HTTP agent, so it cannot resolve the name a second time
 * between our check and the connection.
 *
 * Extracted and exported because getting its SHAPE wrong is invisible to unit tests and
 * fatal in production: Node calls it with options.all on some paths and expects an
 * ARRAY there, and the (err, address, family) form elsewhere. Answering only the second
 * produced "Invalid IP address: undefined" and no brokered request could complete at all.
 */
export function pinnedLookup(address: string, family: number) {
  return (_hostname: string, opts: { all?: boolean } | undefined, cb: (...a: unknown[]) => void) => {
    if (opts && opts.all) return cb(null, [{ address, family }]);
    return cb(null, address, family);
  };
}

/**
 * Addresses no approval can unlock. Cloud metadata endpoints hand out instance
 * credentials; there is no brokered call with a legitimate reason to reach one, so this
 * is not a decision an owner gets to make on an agent's behalf.
 */
const NEVER_APPROVABLE = new Set([
  '169.254.169.254', 'fd00:ec2::254', '100.100.100.200',
]);

/**
 * Is this exact origin one the owner approved for this entry?
 *
 * Exact string match on scheme://host:port, deliberately. A prefix or subnet match would
 * let an approval for 10.0.0.5:9000 cover 10.0.0.50:9000 or port 22 — and a range is a
 * decision an owner cannot realistically evaluate.
 */
export function isApprovedPrivateOrigin(
  origin: { scheme: string; host: string; port: number },
  approved: string[] | undefined,
): boolean {
  if (!approved || approved.length === 0) return false;
  const host = origin.host.toLowerCase();
  if (NEVER_APPROVABLE.has(host)) return false;
  const want = `${origin.scheme}://${host}:${origin.port}`.toLowerCase();
  return approved.some((a) => typeof a === 'string' && a.trim().toLowerCase() === want);
}

/** Resolve once and choose an address, refusing anything internal. */
export function resolvePinned(host: string, allowInternal = false): Promise<{ address: string; family: number }> {
  return new Promise((resolve, reject) => {
    if (isIP(host)) {
      // A literal address still goes through the filter — unless the owner approved this
      // exact origin for this entry, which is the only thing that lifts it.
      if (!allowInternal && isBlockedAddress(host)) {
        return reject(new Error(`refuses to connect to ${host}: internal or reserved address`));
      }
      if (allowInternal && NEVER_APPROVABLE.has(host.toLowerCase())) {
        return reject(new Error(`${host} is a cloud metadata endpoint and cannot be approved`));
      }
      return resolve({ address: host, family: isIP(host) });
    }
    // A stalled resolver would otherwise hang forever: resolution happens BEFORE the
    // total-operation timer is installed, so nothing else would ever settle this.
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`timed out resolving ${host} after ${DNS_TIMEOUT_MS / 1000}s`));
    }, DNS_TIMEOUT_MS);

    dnsLookup(host, { all: true }, (err, addrs) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) return reject(new Error(`could not resolve ${host}: ${err.message}`));
      const usable = addrs.filter((a) =>
        (allowInternal || !isBlockedAddress(a.address))
        && !NEVER_APPROVABLE.has(a.address.toLowerCase()));
      if (usable.length === 0) {
        return reject(new Error(
          `${host} resolves only to internal or reserved addresses (${addrs.map((a) => a.address).join(', ')}); refusing to send the credential there`,
        ));
      }
      resolve({ address: usable[0].address, family: usable[0].family });
    });
  });
}

/**
 * The reply as text, or null when it is not text.
 *
 * Decoded strictly: a reply that is not valid UTF-8, or that carries a NUL byte, is
 * binary whatever its content-type claims, and returning it as a string would hand the
 * caller mangled bytes that look like an answer.
 */
export function asText(raw: Buffer, contentType: string | undefined): string | null {
  const type = (contentType ?? '').toLowerCase();
  if (/^(image|audio|video|font)\//.test(type) || type.startsWith('application/octet-stream')) return null;
  if (raw.includes(0)) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    return null;
  }
}

/** `type/subtype` from a content-type header, or "unknown type". Parameters are dropped. */
export function mediaType(contentType: string | string[] | undefined): string {
  const t = String(Array.isArray(contentType) ? contentType[0] : contentType ?? '').split(';')[0].trim().toLowerCase();
  return /^[a-z0-9!#$&^_.+-]{1,64}\/[a-z0-9!#$&^_.+-]{1,64}$/.test(t) ? t : 'unknown type';
}

function decompressor(encoding: string | undefined) {
  switch ((encoding || '').toLowerCase()) {
    case 'gzip': return createGunzip();
    case 'deflate': return createInflate();
    case 'br': return createBrotliDecompress();
    default: return null;
  }
}

/**
 * Build and send the request described by a verified definition.
 *
 * `secret` is used here and nowhere else — it is not returned, not logged, and not
 * placed anywhere the caller can read.
 */
export async function performOperation(
  def: OperationDefinition,
  /** Typed arguments, sent as JSON — or, for an agent-described request only, a string sent as written. */
  args: Record<string, unknown> | string,
  secret: string,
  /** Exact origins the owner approved for this entry; nothing else lifts the filter. */
  approvedPrivateOrigins?: string[],
): Promise<CallResult> {
  const { scheme, host, port } = def.origin;
  if (scheme !== 'https') return { ok: false, error: 'Only https origins are permitted.' };

  const ownerApproved = isApprovedPrivateOrigin(def.origin, approvedPrivateOrigins);
  let pinned: { address: string; family: number };
  try {
    pinned = await resolvePinned(host, ownerApproved);
  } catch (e) {
    return { ok: false, error: `Refused: ${e instanceof Error ? e.message : String(e)}` };
  }

  const headers: Record<string, string> = { ...(def.static_headers ?? {}) };
  const has = (name: string) => Object.keys(headers).some((k) => k.toLowerCase() === name);
  // Node sends no User-Agent of its own, and GitHub refuses every request without one.
  if (!has('user-agent')) headers['user-agent'] = `wundervault-broker/${VERSION}`;
  let body: string | undefined;
  if (def.route.method !== 'GET' && def.route.method !== 'HEAD') {
    // A string is a body the agent wrote itself — form-encoded for Stripe or Twilio, XML,
    // plain text — and goes as written. Anything else is JSON, as before.
    const isText = typeof args === 'string';
    body = isText ? args : JSON.stringify(args ?? {});
    const maxReq = def.limits?.request_bytes ?? DEFAULT_REQUEST_BYTES;
    if (Buffer.byteLength(body) > maxReq) {
      return { ok: false, error: `Request body exceeds this operation's limit of ${maxReq} bytes.` };
    }
    headers['content-length'] = String(Buffer.byteLength(body));
    if (!has('content-type')) {
      headers['content-type'] = isText ? 'text/plain; charset=utf-8' : 'application/json';
    }
  }

  // The credential goes in last, so nothing in the definition's static headers can
  // shadow it. validateShape already refuses a definition that names both.
  let path = def.route.path;
  const credential = renderCredential(def.credential_binding, secret);
  const forms = secretForms(def.credential_binding, secret);
  if (def.credential_binding.in === 'path') {
    // Checked again here, beside the only line that puts the key in the address: the
    // broker checks before it records or asks for approval, and this must not depend on it.
    const problem = pathBindingProblem(def.credential_binding, secret, path);
    if (problem) return { ok: false, error: `Refused: ${problem} Nothing was sent.` };
    // Only the wire carries the key. def.route.path stays the agent's path, which is what
    // the label, the destination log and the tier-2 record are built from.
    path = pathWithKey(def.credential_binding, secret, path);
  } else if (def.credential_binding.in === 'header') {
    headers[def.credential_binding.name] = credential;
  } else {
    const sep = path.includes('?') ? '&' : '?';
    path += `${sep}${encodeURIComponent(def.credential_binding.name)}=${encodeURIComponent(credential)}`;
  }

  const maxRes = def.limits?.response_bytes ?? DEFAULT_RESPONSE_BYTES;

  // A request that changes something (anything but GET and HEAD) and fails once the
  // connection is up may already have taken effect upstream. Saying only "failed" invites
  // the caller to send it again: a second email, a second order, a second payment.
  const changesSomething = def.route.method !== 'GET' && def.route.method !== 'HEAD';
  let connected = false;
  const mayHaveRun = ' The request may already have reached the service and taken effect; check before sending it again.';

  return await new Promise<CallResult>((resolve) => {
    let settled = false;
    const finish = (r: CallResult) => {
      if (settled) return;
      settled = true;
      // Unknown outcome only: with a status the caller already knows the request arrived.
      if (!r.ok && r.status === undefined && connected && changesSomething) r = { ...r, error: `${r.error}${mayHaveRun}` };
      resolve(r);
    };
    // A 2xx whose reply is too big to return still happened. Reported as a success with
    // nothing shown, not as a failure.
    const tooBig = (status: number, what: string): CallResult => (status >= 200 && status < 300
      ? { ok: true, status, body: `[the reply exceeded ${maxRes} bytes${what}, so none of it is shown; the request itself succeeded]` }
      : { ok: false, status, error: `Upstream returned HTTP ${status}, and its reply exceeded ${maxRes} bytes${what}.` });

    const req = httpsRequest({
      host,
      port,
      path,
      method: def.route.method,
      headers: { ...headers, host },
      // Pin the address we vetted. Without this the agent performs its own lookup at
      // connect time, and the record could differ from the one that passed the check.
      //
      // Node calls this with options.all set on some paths and expects an ARRAY back
      // there, and the (err, address, family) form everywhere else. Answering only the
      // second shape produced "Invalid IP address: undefined" and NO brokered request
      // could complete — a failure no unit test saw, because nothing dialled a real host.
      lookup: pinnedLookup(pinned.address, pinned.family) as unknown as typeof dnsLookup,
      // Certificate and SNI still use the ORIGINAL hostname, so pinning the IP does not
      // weaken TLS verification in the slightest.
      servername: host,
      rejectUnauthorized: true,
      timeout: CONNECT_TIMEOUT_MS,
    }, (res) => {
      const status = res.statusCode ?? 0;

      // A redirect is returned, never followed: following one sends the credential to
      // whatever host the upstream nominates, which is a one-request exfiltration.
      if (status >= 300 && status < 400) {
        res.resume();
        // The Location header is NOT echoed. The upstream has already received the
        // credential, so it can put it anywhere it likes — including Location — and
        // returning that verbatim hands the secret straight back to the caller.
        return finish({
          ok: false, status,
          error: 'Upstream redirected. The redirect is not followed, because the credential would travel with it, and the target is not shown, because an upstream that holds the credential can put it in the Location header. If the destination is legitimate, define an operation for it.',
        });
      }

      const stream = decompressor(res.headers['content-encoding']) ?? res;
      if (stream !== res) res.pipe(stream as NodeJS.WritableStream & NodeJS.ReadableStream);

      let size = 0;
      let wire = 0;
      const chunks: Buffer[] = [];
      let over = false;

      // Cap the WIRE bytes too. Counting only after decompression meant a 20 MiB
      // compressed stream that expands to "{}" downloaded in full before anything
      // noticed — the decompressed cap catches bombs, this one catches the download.
      res.on('data', (c: Buffer) => {
        wire += c.length;
        if (wire > maxRes) {
          over = true;
          req.destroy();
          // Settle HERE. Destroying the request may leave the decompressor with neither
          // 'end' nor 'error', and the promise would hang for the whole total timeout —
          // error handling was attached to the gunzip stream, not to this source.
          finish(tooBig(status, ' on the wire'));
        }
      });
      res.on('error', (e: Error) => finish({ ok: false, status, error: `Response error: ${e.message}` }));
      res.on('aborted', () => finish({ ok: false, status, error: 'Upstream closed the response early.' }));
      (stream as NodeJS.ReadableStream).on('data', (c: Buffer) => {
        // Counted AFTER decompression, so a small compressed bomb cannot expand past
        // the cap unnoticed.
        size += c.length;
        if (size > maxRes) { over = true; req.destroy(); return; }
        chunks.push(c);
      });
      (stream as NodeJS.ReadableStream).on('end', () => {
        if (over) return finish(tooBig(status, ''));
        const ok = status >= 200 && status < 300;
        const scrub = (v: unknown) => forms.reduce<unknown>((acc, f) => scrubSecret(acc, f), v);
        // Without this a 4xx came back as a bare ok:false with no explanation at all.
        // The upstream's own message is not repeated, whatever its type: it holds the
        // credential and could put it in the body. No body at all, here — not left to
        // the caller to drop.
        const raw = Buffer.concat(chunks);
        if (!ok) {
          // A signed operation's owner named the fields the agent may see; an error body is
          // not one of them.
          if (def.response !== undefined) {
            return finish({
              ok: false, status,
              error: `Upstream returned HTTP ${status}. This operation returns only the fields its owner named, so the service's explanation is not shown.`,
            });
          }
          // An agent-described request gets the service's explanation, scrubbed exactly as a
          // success is — otherwise it cannot see what to fix. Withholding it guarded nothing
          // the success path does not already return.
          const detailText = raw.length > 0 ? asText(raw, res.headers['content-type']) : '';
          let detail: unknown;
          if (detailText === null) detail = `[${raw.length} bytes of ${scrub(mediaType(res.headers['content-type']))}, not text, so not shown]`;
          else if (detailText.length > 0) {
            try { detail = JSON.parse(detailText); } catch { detail = detailText; }
            // A body of `null` is the service saying null, not an empty reply (round 2, F2).
            if (detail === null) detail = detailText;
            detail = scrub(detail);
          }
          return finish({
            ok: false, status,
            ...(detail !== undefined ? { body: detail } : {}),
            error: `Upstream returned HTTP ${status}.`,
          });
        }
        // Decoded STRICTLY before anything parses it. A lenient decode turned invalid bytes
        // into U+FFFD and JSON.parse then accepted them, so bytes the text rules refuse came
        // back as data (round 2, F2). Bytes that are not text are never parsed as JSON.
        const text = raw.length > 0 ? asText(raw, res.headers['content-type']) : '';
        // An empty reply is an answer, not a parse failure: a DELETE that returns 204 did
        // what it was asked. Reporting it as a failure invites the caller to send it again.
        let parsed: unknown = null;
        if (text === null) parsed = undefined;
        else if (text.length > 0) {
          try { parsed = JSON.parse(text); } catch { parsed = undefined; }
        }
        if (parsed === undefined) {
          // The upstream chose this header and holds the key, so it is reduced to a bare
          // media type and scrubbed before it is repeated in a description.
          const kind = scrub(mediaType(res.headers['content-type'])) as string;
          // A signed definition's allowlist names JSON fields. A reply it cannot parse
          // cannot be filtered, so none of it is returned — but the request went
          // through, and ok says so: a caller told a payment failed pays again.
          if (def.response !== undefined) {
            return finish({
              ok: true, status,
              body: `[${raw.length} bytes of ${kind}, not JSON; this operation returns only named JSON fields, so none of the reply is shown]`,
            });
          }
          // An agent-described request has no allowlist: plain text, CSV and HTML come
          // back as text, scrubbed like everything else. Bytes that are not text are
          // described, never returned.
          return finish({
            ok: true, status,
            body: text === null ? `[${raw.length} bytes of ${kind}, not text, so not shown]` : scrub(text),
          });
        }
        // Only the fields the definition allows reach the caller — and even then the
        // secret is scrubbed, because an upstream can echo it in an ALLOWED field and
        // the allowlist alone would pass it through.
        finish({ ok: true, status, body: scrub(filterResponse(def, parsed)) });
      });
      (stream as NodeJS.ReadableStream).on('error', (e: Error) => finish({ ok: false, status, error: `Response error: ${e.message}` }));
    });

    const total = setTimeout(() => { req.destroy(); finish({ ok: false, error: `Operation timed out after ${TOTAL_TIMEOUT_MS / 1000}s.` }); }, TOTAL_TIMEOUT_MS);
    req.on('close', () => clearTimeout(total));
    req.on('timeout', () => { req.destroy(); finish({ ok: false, error: 'Connection timed out.' }); });
    req.on('socket', (sock) => { sock.once('secureConnect', () => { connected = true; }); });
    req.on('error', (e) => finish({ ok: false, error: `Request failed: ${e.message}` }));

    if (body) req.write(body);
    req.end();
  });
}


// ── tiered brokering ───────────────────────────────────────────────────────────

/**
 * A request the AGENT described, rather than one a signed definition fixed.
 *
 * This is the tier-1 shape: the agent knows where it is going because the secret's name
 * and the user's prompt told it. What it does not get, at any tier, is the credential
 * itself or a say in how the credential is framed.
 */
export interface AgentRequest {
  origin: { scheme: string; host: string; port: number };
  method: string;
  path: string;
  body?: unknown;
  query?: Record<string, string>;
  /**
   * Headers the agent sets — a User-Agent, an API version, a content-type for a body it
   * wrote. Checked in the broker (delivery.ts validateAgentHeaders) before they arrive
   * here; the credential is written after them and its header name is refused.
   */
  headers?: Record<string, string>;
}

/**
 * Turn an agent-described request into the definition shape the executor already takes.
 *
 * The credential binding comes from the ENTRY, never from the agent: an agent may choose
 * where to send a request, never how the secret is framed on the way out. Without a
 * signed definition there is no response allowlist, so everything comes back — scrubbed,
 * which catches the credential verbatim and not an encoded copy. That is the honest
 * difference between this tier and a typed adapter.
 */
export function definitionFromAgentRequest(
  req: AgentRequest,
  binding: CredentialBinding,
  limits?: { request_bytes?: number; response_bytes?: number },
): OperationDefinition {
  let path = req.path || '/';
  if (req.query && Object.keys(req.query).length > 0) {
    const qs = Object.entries(req.query)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
    path += (path.includes('?') ? '&' : '?') + qs;
  }
  return {
    op: 'agent.request',
    origin: req.origin,
    route: { method: (req.method || 'GET').toUpperCase(), path },
    credential_binding: binding,
    ...(req.headers && Object.keys(req.headers).length > 0 ? { static_headers: { ...req.headers } } : {}),
    // No allowlist: an unsigned request has nothing describing its response, so the
    // caller gets the body. `response.allow` with a single '*' would be a lie; the
    // executor treats an absent allow-list as "return everything", and scrubSecret still
    // runs over it.
    response: undefined,
    redirects: 'deny',
    limits,
  } as OperationDefinition;
}

/** Canonical origin string, for the server-side approval check and the audit row. */
export function originString(o: { scheme: string; host: string; port: number }): string {
  return `${o.scheme}://${o.host}:${o.port}`;
}
