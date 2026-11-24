/**
 * Agent proposals wait for the owner's passkey approval. They are not job orders and
 * cannot be applied to the helper's job store.
 */
import { randomBytes } from 'node:crypto';
import { validateJobOrder, type JobDefinition } from './jobs.js';
import { sealForOwner } from './server-setup.js';

export type JobProposal = Pick<JobDefinition,
  'name' | 'entry_id' | 'destination' | 'argv' | 'schedule' | 'timeout_s' | 'file'
> & {
  grace_minutes: number;
  why: string;
};

const FIELDS = [
  'name', 'entry_id', 'destination', 'argv', 'schedule', 'timeout_s', 'grace_minutes', 'why', 'file',
];
const REQUIRED = ['name', 'entry_id', 'destination', 'argv', 'schedule', 'why'];

export function validateJobProposal(
  input: unknown,
): { ok: true; proposal: JobProposal } | { ok: false; reason: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, reason: 'malformed proposal' };
  }
  const o = input as Record<string, unknown>;
  if (Object.keys(o).some(k => !FIELDS.includes(k)) ||
      !REQUIRED.every(k => Object.hasOwn(o, k))) {
    return { ok: false, reason: 'malformed proposal' };
  }
  if (typeof o.why !== 'string' || !/^[^\p{Cc}]{1,300}$/u.test(o.why) || !o.why.trim()) {
    return { ok: false, reason: 'why must be 1 to 300 characters, without control characters' };
  }
  const grace = o.grace_minutes === undefined ? 30 : o.grace_minutes;
  if (!Number.isInteger(grace) || (grace as number) < 5 || (grace as number) > 1440) {
    return { ok: false, reason: 'grace_minutes must be an integer from 5 to 1440' };
  }

  // Use the order validator itself, not a second copy of its field rules. This
  // synthetic envelope is only for validation; it is never stored or applied.
  const checked = validateJobOrder({
    v: 1, type: 'job-set', broker: 'proposal',
    order_id: 'proposal', job_id: 'proposal', version: 1,
    issued_at: '1970-01-01T00:00:00.000Z',
    expires_at: '1970-01-01T00:01:00.000Z',
    name: o.name, entry_id: o.entry_id, destination: o.destination,
    argv: o.argv, schedule: o.schedule,
    timeout_s: o.timeout_s === undefined ? 300 : o.timeout_s,
    ...(Object.hasOwn(o, 'file') ? { file: o.file } : {}),
  }, 'proposal', 0);
  if (!checked.ok && checked.reason === 'bad file') {
    return { ok: false, reason: 'file must be { max_bytes: 1 to 2147483648, keep: 1 to 14 }' };
  }
  if (!checked.ok) return checked;

  const job = checked.job;
  return {
    ok: true,
    proposal: {
      name: job.name, entry_id: job.entry_id, destination: job.destination,
      argv: job.argv, schedule: job.schedule, timeout_s: job.timeout_s,
      grace_minutes: grace as number, why: o.why,
      ...(job.file ? { file: job.file } : {}),
    },
  };
}

export function sealProposal(
  vaultKey: Uint8Array,
  requestId: string,
  proposal: JobProposal,
  agentName: string,
  nowIso: string,
): { ciphertext: string; nonce: string } {
  return sealForOwner(vaultKey, `wv-job-request-v1|${requestId}`, {
    v: 1,
    type: 'job-request',
    request_id: requestId,
    agent_name: agentName,
    created_at: nowIso,
    name: proposal.name,
    entry_id: proposal.entry_id,
    destination: proposal.destination,
    argv: proposal.argv,
    schedule: proposal.schedule,
    timeout_s: proposal.timeout_s,
    grace_minutes: proposal.grace_minutes,
    why: proposal.why,
    ...(proposal.file ? { file: proposal.file } : {}),
  });
}

export function newRequestId(): string {
  return randomBytes(18).toString('base64url');
}
