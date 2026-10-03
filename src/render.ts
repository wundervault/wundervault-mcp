/**
 * How a call's reply is shown to the agent — used by the MCP server for a success and by the
 * broker for a refusal's detail.
 *
 * Its own module, with no imports, so the broker can use it without pulling in the MCP
 * server and the server can use it without importing anything that decrypts
 * (key-custody.test.ts greps the server's imports for exactly that).
 */

/** A reply as text: as written for a string, said in words when empty, JSON indented. */
export function renderBody(body: unknown): string {
  if (body === null || body === undefined) return '(empty reply)';
  if (typeof body === 'string') return body;
  return JSON.stringify(body, null, 2);
}

/** The most of a refusal's detail an agent is shown, in UTF-8 bytes. A whole HTML error page is not. */
export const MAX_DETAIL_BYTES = 16 * 1024;

/**
 * A refusal's detail, cut to a bound. The caller has ALREADY scrubbed it: cutting first
 * could leave half a key on one side of the cut, which no exact-match scrub then finds.
 *
 * Measured in bytes, not string length: 16,000 `é` is 16,000 characters and 32,000 bytes
 * (round 1, F1). A character split by the cut is dropped, not shown as a replacement mark.
 */
export function renderDetail(scrubbed: unknown): string {
  const text = renderBody(scrubbed);
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= MAX_DETAIL_BYTES) return text;
  return `${bytes.subarray(0, MAX_DETAIL_BYTES).toString('utf8').replace(/\uFFFD+$/, '')}\n[… truncated]`;
}
