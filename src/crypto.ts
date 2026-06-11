import crypto from 'node:crypto';

/**
 * Decode a URL-safe base64 encryption key to 32 raw bytes.
 * Input: URL-safe base64 with - and _ (no = padding)
 * Output: exactly 32 bytes (AES-256 key)
 */
export function loadEncryptionKey(key: string): Uint8Array {
  if (!key) throw new Error('Encryption key is empty');
  // URL-safe → standard base64: - → +, _ → /
  const standard = key.replace(/-/g, '+').replace(/_/g, '/');
  // Add = padding until length is divisible by 4
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  const decoded = Buffer.from(padded, 'base64');
  if (decoded.length !== 32) {
    throw new Error(
      `Encryption key must be 32 bytes, got ${decoded.length}. ` +
      `Use the "Encryption Key" field from your agent setup page — ` +
      `not the API key or the HMAC suffix after the "|" in the API key. ` +
      `Set WUNDERVAULT_AGENT_ENCRYPTION_KEY (or check agent_encryption_key in ~/.wundervault/creds.json).`
    );
  }
  return new Uint8Array(decoded);
}

/**
 * HMAC-SHA256(apiKey, encKey) → base64.
 * Matches server's hmac_key column.
 */
export function hmacForApiKey(apiKey: string, encKey: Uint8Array): string {
  return crypto.createHmac('sha256', Buffer.from(encKey))
    .update(apiKey)
    .digest('base64');
}

/**
 * Verify directive signature: PBKDF2-HMAC-SHA256, 600k iterations.
 * Salt = first 16 bytes of base64-decoded signature.
 * Sig = remaining bytes of base64-decoded signature.
 * Uses timing-safe comparison.
 */
export function verifyDirectiveSignature(
  directive: string,
  signature: string,
  plaintext: Uint8Array
): boolean {
  if (!signature || !plaintext || plaintext.length === 0) return false;
  try {
    const raw = Buffer.from(signature, 'base64');
    if (raw.length < 16 + 32) return false; // need at least 16-byte salt + 32-byte sig
    const salt = raw.subarray(0, 16);
    const expectedSig = raw.subarray(16);
    // CORRECT pbkdf2Sync argument order: (password, salt, iterations, keylen, digest)
    const key = crypto.pbkdf2Sync(Buffer.from(plaintext), salt, 600_000, 32, 'sha256');
    const actual = crypto.createHmac('sha256', Buffer.from(key))
      .update(directive)
      .digest();
    return crypto.timingSafeEqual(actual, expectedSig);
  } catch {
    return false;
  }
}

/**
 * AES-256-GCM decrypt helper. Auth tag is the last 16 bytes of ciphertext.
 */
function aesGcmDecrypt(key: Uint8Array, nonce: Buffer, ciphertextWithTag: Buffer): Buffer {
  if (ciphertextWithTag.length < 16) {
    throw new Error('Ciphertext too short to contain GCM auth tag');
  }
  const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/**
 * Decode base64 (URL-safe or standard) with minimal padding fix.
 */
function b64Decode(s: string): Buffer {
  const standard = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

/**
 * Decrypt vault_key_for_agent blob: AES-256-GCM.
 * Blob format: 60 raw bytes = 12B nonce + 32B ciphertext + 16B GCM tag (nonce-prepended).
 * Input blob: base64-encoded string.
 */
export function decryptVaultKey(encKey: Uint8Array, blobB64: string): Uint8Array {
  const blob = b64Decode(blobB64);
  if (blob.length < 12 + 16) {
    throw new Error(`Vault key blob too short: ${blob.length} bytes`);
  }
  const nonce = blob.subarray(0, 12);
  const ciphertextWithTag = blob.subarray(12);
  return new Uint8Array(aesGcmDecrypt(encKey, nonce, ciphertextWithTag));
}

/**
 * Decrypt a vault secret's encrypted_content field using the vault key.
 * encrypted_content and content_nonce are SEPARATE base64 fields (from API response).
 * Content blob: ciphertext + GCM tag (no nonce prepended — nonce is separate field).
 */
export function decryptSecretContent(
  vaultKey: Uint8Array,
  encryptedContentB64: string,
  contentNonceB64: string
): Uint8Array {
  const ciphertextWithTag = b64Decode(encryptedContentB64);
  const nonce = b64Decode(contentNonceB64);
  return new Uint8Array(aesGcmDecrypt(vaultKey, nonce, ciphertextWithTag));
}