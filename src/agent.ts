#!/usr/bin/env node

import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { VERSION } from './version.js';

const WUNDERVAULT_DIR = path.join(os.homedir(), '.wundervault');
const AGENTS_DIR = path.join(WUNDERVAULT_DIR, 'agents');
const PROFILES_PATH = path.join(WUNDERVAULT_DIR, 'agent-profiles.enc');
const MGMT_SOCK = path.join(WUNDERVAULT_DIR, 'agent.sock');
const SALT_PATH = path.join(WUNDERVAULT_DIR, 'agent-salt.bin');

interface AgentProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

interface ProfileStore {
  profiles: AgentProfile[];
}

function deriveMachineKey(): Buffer {
  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch {}
  const uid = (process as any).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();

  let salt: Buffer;
  if (fs.existsSync(SALT_PATH)) {
    salt = fs.readFileSync(SALT_PATH);
  } else {
    salt = crypto.randomBytes(32);
    fs.mkdirSync(WUNDERVAULT_DIR, { recursive: true });
    fs.writeFileSync(SALT_PATH, salt, { mode: 0o600 });
  }

  return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
}

function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(store), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, encrypted]);
}

function decryptProfiles(buf: Buffer, key: Buffer): ProfileStore {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

class AgentDaemon {
  private key: Buffer;
  private profiles: AgentProfile[] = [];
  private agentServers: Map<string, net.Server> = new Map();
  private mgmtServer: net.Server | null = null;

  constructor() {
    this.key = deriveMachineKey();
    this.loadProfiles();
  }

  loadProfiles(): void {
    if (fs.existsSync(PROFILES_PATH)) {
      try {
        const buf = fs.readFileSync(PROFILES_PATH);
        this.profiles = decryptProfiles(buf, this.key).profiles;
      } catch (err) {
        console.error('[wundervault-agent] Failed to decrypt profiles:', (err as Error).message);
      }
    }
  }

  saveProfiles(): void {
    const buf = encryptProfiles({ profiles: this.profiles }, this.key);
    fs.writeFileSync(PROFILES_PATH, buf, { mode: 0o600 });
  }

  registerProfile(profile: AgentProfile): void {
    const idx = this.profiles.findIndex(p => p.agent_name === profile.agent_name);
    if (idx >= 0) {
      this.profiles[idx] = profile;
      // Close and restart the socket so the handler uses the updated token/creds.
      const old = this.agentServers.get(profile.agent_name);
      if (old) {
        // Don't unlink the socket in the close callback — startAgentSocket
        // unlinks and rebinds immediately, and the async callback would race it.
        old.close();
        this.agentServers.delete(profile.agent_name);
      }
      this.startAgentSocket(profile);
    } else {
      this.profiles.push(profile);
      this.startAgentSocket(profile);
    }
    this.saveProfiles();
  }

  startAgentSocket(profile: AgentProfile): void {
    const sockPath = path.join(AGENTS_DIR, `${profile.agent_name}.sock`);
    try { fs.unlinkSync(sockPath); } catch {}

    const srv = net.createServer((socket) => {
      let buf = '';
      socket.on('data', (d) => {
        buf += d.toString();
        if (buf.includes('\n')) {
          if (profile.socket_token) {
            let msg: { token?: string } = {};
            try { msg = JSON.parse(buf.trim()); } catch {}
            const provided = msg.token ? Buffer.from(msg.token, 'hex') : Buffer.alloc(0);
            const expected = Buffer.from(profile.socket_token, 'hex');
            if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
              console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
              return;
            }
          }
          const res = JSON.stringify({
            api_key: profile.api_key,
            enc_key: profile.enc_key,
            vault_url: profile.vault_url,
          });
          socket.write(res + '\n');
          socket.end();
        }
      });
      socket.on('error', () => {});
    });

    srv.listen(sockPath, () => {
      try { fs.chmodSync(sockPath, 0o600); } catch {}
    });
    srv.on('error', (err) => {
      console.error(`[wundervault-agent] Socket error for ${profile.agent_name}:`, err.message);
    });
    this.agentServers.set(profile.agent_name, srv);
  }

  startMgmtSocket(): void {
    try { fs.unlinkSync(MGMT_SOCK); } catch {}

    const mgmt = net.createServer((socket) => {
      let buf = '';
      socket.on('data', (d) => {
        buf += d.toString();
        const nl = buf.indexOf('\n');
        if (nl >= 0) {
          try {
            const msg = JSON.parse(buf.slice(0, nl));
            if (msg.action === 'register_profile' && msg.profile) {
              this.registerProfile(msg.profile as AgentProfile);
              socket.write(JSON.stringify({ ok: true }) + '\n');
            } else if (msg.action === 'reload') {
              this.loadProfiles();
              socket.write(JSON.stringify({ ok: true, count: this.profiles.length }) + '\n');
            } else if (msg.action === 'ping') {
              socket.write(JSON.stringify({ ok: true, version: VERSION, agents: this.profiles.map(p => p.agent_name) }) + '\n');
            } else {
              socket.write(JSON.stringify({ error: 'unknown action' }) + '\n');
            }
          } catch {
            socket.write(JSON.stringify({ error: 'parse error' }) + '\n');
          }
          socket.end();
        }
      });
      socket.on('error', () => {});
    });

    mgmt.listen(MGMT_SOCK, () => {
      try { fs.chmodSync(MGMT_SOCK, 0o600); } catch {}
      console.log(`[wundervault-agent] Listening. Management: ${MGMT_SOCK}`);
    });
    mgmt.on('error', (err) => {
      console.error('[wundervault-agent] Mgmt socket error:', err.message);
    });
    this.mgmtServer = mgmt;
  }

  start(): void {
    fs.mkdirSync(AGENTS_DIR, { recursive: true });
    // Remove any stale socket files left by a previous crash
    try {
      for (const f of fs.readdirSync(AGENTS_DIR)) {
        if (f.endsWith('.sock')) {
          try { fs.unlinkSync(path.join(AGENTS_DIR, f)); } catch {}
        }
      }
    } catch {}
    for (const profile of this.profiles) {
      this.startAgentSocket(profile);
    }
    this.startMgmtSocket();
    console.log(`[wundervault-agent] Started with ${this.profiles.length} agent(s).`);
  }

  shutdown(): void {
    for (const [name, srv] of this.agentServers) {
      try { srv.close(); } catch {}
      try { fs.unlinkSync(path.join(AGENTS_DIR, `${name}.sock`)); } catch {}
    }
    if (this.mgmtServer) {
      try { this.mgmtServer.close(); } catch {}
    }
    try { fs.unlinkSync(MGMT_SOCK); } catch {}
  }
}

const daemon = new AgentDaemon();
daemon.start();
process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
process.on('SIGINT', () => { daemon.shutdown(); process.exit(0); });