import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { loadEncryptionKey, hmacForApiKey, verifyDirectiveSignature } from '../src/crypto.js';
import { runWithSecret } from '../src/exec.js';
import { loadCredentials } from '../src/server.js';

// ── Crypto: loadEncryptionKey ─────────────────────────────────────────────────

describe('loadEncryptionKey', () => {
  it('decodes a URL-safe base64 key to exactly 32 bytes', () => {
    // 32 random bytes → URL-safe base64 (no padding)
    const raw = crypto.randomBytes(32);
    const b64 = raw.toString('base64url'); // URL-safe, no = padding
    const result = loadEncryptionKey(b64);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it('handles keys with - and _ characters (URL-safe)', () => {
    // Craft a key that will have - and _ after URL-safe encoding
    // Just use a known key that has both
    const raw = Buffer.alloc(32, 0xff); // all 0xff bytes → //// in standard b64
    const standard = raw.toString('base64');    // standard base64
    const urlSafe = standard.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const result = loadEncryptionKey(urlSafe);
    expect(result.length).toBe(32);
    expect(Buffer.from(result).equals(raw)).toBe(true);
  });

  it('throws for empty key', () => {
    expect(() => loadEncryptionKey('')).toThrow('Encryption key is empty');
  });
});

// ── Crypto: hmacForApiKey ─────────────────────────────────────────────────────

describe('hmacForApiKey', () => {
  it('returns a non-empty base64 string', () => {
    const encKey = crypto.randomBytes(32);
    const result = hmacForApiKey('wv_agent_test|suffix', new Uint8Array(encKey));
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    // Should be valid base64
    expect(() => Buffer.from(result, 'base64')).not.toThrow();
  });

  it('matches Python: HMAC-SHA256(key=encKey, data=apiKey)', () => {
    const encKey = Buffer.from('a'.repeat(32));
    const apiKey = 'wv_agent_abc|def';
    const expected = crypto.createHmac('sha256', encKey).update(apiKey).digest('base64');
    const result = hmacForApiKey(apiKey, new Uint8Array(encKey));
    expect(result).toBe(expected);
  });
});

// ── Crypto: verifyDirectiveSignature ─────────────────────────────────────────

describe('verifyDirectiveSignature', () => {
  function makeSignature(directive: string, plaintext: Buffer): string {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(plaintext, salt, 600_000, 32, 'sha256');
    const sig = crypto.createHmac('sha256', key).update(directive).digest();
    return Buffer.concat([salt, sig]).toString('base64');
  }

  it('returns true for a valid signature', () => {
    const directive = 'burn after reading';
    const plaintext = Buffer.from('my-secret-value');
    const signature = makeSignature(directive, plaintext);
    expect(verifyDirectiveSignature(directive, signature, new Uint8Array(plaintext))).toBe(true);
  });

  it('returns false for a tampered signature', () => {
    const directive = 'burn after reading';
    const plaintext = Buffer.from('my-secret-value');
    const signature = makeSignature(directive, plaintext);
    // Flip a byte in the signature
    const raw = Buffer.from(signature, 'base64');
    raw[20] ^= 0xff;
    const tampered = raw.toString('base64');
    expect(verifyDirectiveSignature(directive, tampered, new Uint8Array(plaintext))).toBe(false);
  });

  it('returns false for wrong plaintext', () => {
    const directive = 'burn after reading';
    const plaintext = Buffer.from('my-secret-value');
    const signature = makeSignature(directive, plaintext);
    const wrong = Buffer.from('wrong-secret');
    expect(verifyDirectiveSignature(directive, signature, new Uint8Array(wrong))).toBe(false);
  });

  it('returns false for empty signature', () => {
    expect(verifyDirectiveSignature('directive', '', new Uint8Array(Buffer.from('secret')))).toBe(false);
  });

  it('returns false for empty plaintext', () => {
    expect(verifyDirectiveSignature('directive', 'abc', new Uint8Array(0))).toBe(false);
  });
});

// ── exec: runWithSecret ───────────────────────────────────────────────────────

describe('runWithSecret', () => {
  it('scrubs plaintext from stdout', () => {
    const secret = 'supersecret123';
    const { stdout } = runWithSecret(secret, `echo ${secret}`);
    expect(stdout).not.toContain(secret);
    expect(stdout).toContain('[SECRET_REDACTED]');
  });

  it('scrubs plaintext from stderr', () => {
    const secret = 'supersecret456';
    const { stderr } = runWithSecret(secret, `echo ${secret} >&2`);
    expect(stderr).not.toContain(secret);
    expect(stderr).toContain('[SECRET_REDACTED]');
  });

  it('returns exit code 0 for a successful command', () => {
    const { exitCode } = runWithSecret('x', 'exit 0');
    expect(exitCode).toBe(0);
  });

  it('returns non-zero exit code for a failing command', () => {
    const { exitCode } = runWithSecret('x', 'exit 42');
    expect(exitCode).toBe(42);
  });

  it('makes secret available as $WUNDERVault_SECRET env var', () => {
    const secret = 'injected_value_abc';
    const { stdout, exitCode } = runWithSecret(secret, 'echo $WUNDERVault_SECRET');
    // stdout will be scrubbed, but we can verify the command ran successfully
    // and the secret was available (it got scrubbed = it was there)
    expect(exitCode).toBe(0);
    expect(stdout).toContain('[SECRET_REDACTED]');
  });
});

// ── Credentials: loadCredentials ─────────────────────────────────────────────

describe('loadCredentials', () => {
  it('prefers env vars over nothing', () => {
    const origApiKey = process.env['WUNDERVault_AGENT_VAULT_API_KEY'];
    const origEncKey = process.env['WUNDERVault_AGENT_KEY'];
    process.env['WUNDERVault_AGENT_VAULT_API_KEY'] = 'env_api_key';
    process.env['WUNDERVault_AGENT_KEY'] = 'ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVl'; // 32-char base64
    try {
      const creds = loadCredentials({});
      expect(creds.agent_vault_api_key).toBe('env_api_key');
    } finally {
      if (origApiKey === undefined) delete process.env['WUNDERVault_AGENT_VAULT_API_KEY'];
      else process.env['WUNDERVault_AGENT_VAULT_API_KEY'] = origApiKey;
      if (origEncKey === undefined) delete process.env['WUNDERVault_AGENT_KEY'];
      else process.env['WUNDERVault_AGENT_KEY'] = origEncKey;
    }
  });

  it('returns empty credentials when none are available', () => {
    // Use a credentials path that doesn't exist
    const origApiKey = process.env['WUNDERVault_AGENT_VAULT_API_KEY'];
    const origEncKey = process.env['WUNDERVault_AGENT_KEY'];
    delete process.env['WUNDERVault_AGENT_VAULT_API_KEY'];
    delete process.env['WUNDERVault_AGENT_KEY'];
    try {
      const creds = loadCredentials({ credentials: '/nonexistent/path/creds.json' });
      // Should return with empty strings rather than throwing
      expect(creds.agent_vault_api_key).toBe('');
      expect(creds.agent_encryption_key).toBe('');
      expect(creds.agent_vault_url).toBe('https://wundervault.com');
    } finally {
      if (origApiKey !== undefined) process.env['WUNDERVault_AGENT_VAULT_API_KEY'] = origApiKey;
      if (origEncKey !== undefined) process.env['WUNDERVault_AGENT_KEY'] = origEncKey;
    }
  });
});
