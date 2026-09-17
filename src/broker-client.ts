/**
 * The MCP server's side of the broker socket.
 *
 * This process runs as the AGENT's uid. It used to ask the broker for credentials and do
 * everything itself; it now asks the broker to do the work and receives only results. The
 * difference is the whole of this phase: `enc_key` never arrives here, so `vault_key` is
 * never derived here, so this process cannot read an entry the broker declines to give it.
 *
 * WHAT THIS FILE MUST NOT GROW
 *
 * No decryption. Nothing here imports `decryptVaultKey`, `decryptSecretContent` or
 * `loadEncryptionKey`, and a test greps for exactly that — because the natural way to
 * "fix" a future bug here is to fetch the ciphertext and open it locally, which would
 * quietly reinstate the thing the phase removed.
 */
import net from 'node:net';
import { existsSync, readFileSync } from 'node:fs';
import { agentSocketPath, agentTokenPath, legacy } from './paths.js';

/** Long enough for a brokered HTTP call (30s upstream) and a tier-2 wait (~90s). */
const RPC_TIMEOUT_MS = 150_000;
const MAX_REPLY_BYTES = 8 * 1024 * 1024;

export class BrokerUnavailable extends Error {}
export class BrokerUpgradeRequired extends Error {}

export interface BrokerReply { [k: string]: unknown; error?: string; code?: string }

function socketCandidates(agentName: string): Array<{ path: string; legacy: boolean }> {
  const primary = agentSocketPath(agentName);
  const out = [{ path: primary, legacy: false }];
  const old = legacy.agentSocket(agentName);
  if (old !== primary) out.push({ path: old, legacy: true });
  return out;
}

export class BrokerClient {
  private token: string;
  private warnedLegacy = false;

  constructor(public readonly agentName: string) {
    const tokenPath = agentTokenPath(agentName);
    this.token = process.env.WUNDERVAULT_AGENT_TOKEN
      || (existsSync(tokenPath) ? readFileSync(tokenPath, 'utf8').trim() : '');
  }

  /**
   * One request, one reply, one connection.
   *
   * Deliberately not pooled. A pooled connection would have to be kept alive across tool
   * calls, and the broker's absolute deadline closes it underneath us; reconnecting per
   * call costs a unix-socket connect and removes a whole class of "it worked until it
   * had been idle for two minutes" bug.
   */
  private rpc(sockPath: string, payload: Record<string, unknown>): Promise<BrokerReply> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(sockPath);
      let buf = '';
      let done = false;
      const finish = (fn: () => void) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { socket.destroy(); } catch { /* already gone */ }
        fn();
      };
      const timer = setTimeout(
        () => finish(() => reject(new BrokerUnavailable(
          `The secret broker did not answer within ${Math.round(RPC_TIMEOUT_MS / 1000)}s.`))),
        RPC_TIMEOUT_MS,
      );
      socket.on('connect', () => {
        socket.write(JSON.stringify({ token: this.token, ...payload }) + '\n');
      });
      socket.on('data', (d) => {
        buf += d.toString();
        // A reply is bounded so a broken or hostile socket cannot grow this without end.
        // The broker is trusted here — it is the more privileged party — but "trusted"
        // is not a reason to leave an unbounded buffer on the less privileged side.
        if (buf.length > MAX_REPLY_BYTES) {
          finish(() => reject(new BrokerUnavailable('The broker sent an oversized reply.')));
          return;
        }
        if (!buf.includes('\n')) return;
        finish(() => {
          try { resolve(JSON.parse(buf.trim()) as BrokerReply); }
          catch { reject(new BrokerUnavailable('The broker sent a reply this build could not parse.')); }
        });
      });
      socket.on('error', (e) => finish(() => reject(new BrokerUnavailable(
        `Could not reach the secret broker at ${sockPath}: ${(e as Error).message}`))));
      socket.on('end', () => {
        if (!buf.includes('\n')) {
          finish(() => reject(new BrokerUnavailable('The broker closed the connection without replying.')));
        }
      });
    });
  }

  /**
   * Send an operation to whichever socket answers.
   *
   * The pre-split socket in the user's home is still tried, because a machine mid-
   * migration has to keep working — and it ANNOUNCES itself, because that install has the
   * old threat model while the release notes describe the new one.
   */
  async send(op: string, payload: Record<string, unknown> = {}): Promise<BrokerReply> {
    if (!this.token) {
      throw new BrokerUnavailable(
        `No token for agent '${this.agentName}'. Expected ${agentTokenPath(this.agentName)} `
        + `or WUNDERVAULT_AGENT_TOKEN. Re-run enrolment: wundervault-agent --enrol`);
    }
    let lastErr: Error | null = null;
    for (const cand of socketCandidates(this.agentName)) {
      if (!existsSync(cand.path)) continue;
      try {
        const reply = await this.rpc(cand.path, { op, ...payload });
        if (cand.legacy && !this.warnedLegacy) {
          this.warnedLegacy = true;
          process.stderr.write(
            `[wundervault] Using the pre-split broker socket at ${cand.path}.\n`
            + `[wundervault] That process runs as YOUR user, so its key material and memory\n`
            + `[wundervault] are readable by anything you run, including your agents.\n`
            + `[wundervault] Finish the split: sudo sh packaging/install-daemon.sh\n`);
        }
        if (reply?.code === 'UPGRADE_REQUIRED') {
          throw new BrokerUpgradeRequired(String(reply.error ?? 'This MCP server is too old for this broker.'));
        }
        return reply;
      } catch (e) {
        if (e instanceof BrokerUpgradeRequired) throw e;
        lastErr = e as Error;
      }
    }
    throw new BrokerUnavailable(
      lastErr?.message
      ?? `wundervault-agent is not running for agent '${this.agentName}'.\n`
         + `Expected socket: ${agentSocketPath(this.agentName)}\n`
         + `Install the broker: sudo sh packaging/install-daemon.sh\n`
         + `Then enrol:        wundervault-agent --enrol`);
  }

  /**
   * Send, and turn `{error}` into a thrown error.
   *
   * Two call styles exist on purpose. Tools that want to render a refusal as a tool
   * result use `send` and read `.error`; everything else uses this and lets the handler's
   * catch turn it into a message.
   */
  async sendOrThrow(op: string, payload: Record<string, unknown> = {}): Promise<BrokerReply> {
    const reply = await this.send(op, payload);
    if (reply?.error) {
      const e = new Error(String(reply.error));
      (e as Error & { code?: string }).code = reply.code ? String(reply.code) : undefined;
      throw e;
    }
    return reply;
  }
}

let _client: BrokerClient | null = null;

export function brokerClient(): BrokerClient {
  if (_client) return _client;
  const agentName = process.env.WUNDERVAULT_AGENT_NAME;
  if (!agentName) {
    throw new BrokerUnavailable(
      'WUNDERVAULT_AGENT_NAME is not set.\n'
      + 'Add env: {"WUNDERVAULT_AGENT_NAME": "<name>"} to your MCP config and re-run enrolment.');
  }
  _client = new BrokerClient(agentName);
  return _client;
}

/** Test seam. */
export function _resetBrokerClient(): void { _client = null; }
