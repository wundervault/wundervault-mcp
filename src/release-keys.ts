export interface ReleaseKey {
  id: string;
  publicKey: string; // Base64 of the raw 32-byte ed25519 key.
  test?: boolean;
}

/**
 * The owner's production key is added at release setup.
 *
 * Test builds replace this file with scripts/use-test-key.mjs. CI refuses a release
 * whose list holds a key with test:true, so a test signer cannot ship by accident.
 */
export const RELEASE_KEYS: readonly ReleaseKey[] = [];
