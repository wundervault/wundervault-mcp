import { RELEASE_KEYS } from '../dist/release-keys.js';
import { args, base64, main } from './lib/release-cli.mjs';

main(() => {
  const values = args({ 'allow-empty': { type: 'boolean', default: false } });
  if (!Array.isArray(RELEASE_KEYS)) throw new Error('RELEASE_KEYS must be an array');
  if (!RELEASE_KEYS.length && !values['allow-empty']) {
    throw new Error('RELEASE_KEYS is empty: a release with no owner key can never self-update');
  }
  const ids = new Set();
  for (const key of RELEASE_KEYS) {
    if (!key || typeof key.id !== 'string' || !key.id) throw new Error('Release key has no id');
    if (ids.has(key.id)) throw new Error(`Duplicate release key id: ${key.id}`);
    ids.add(key.id);
    if (key.test === true) throw new Error(`TEST release key refused: ${key.id}`);
    base64(key.publicKey, 32, `Release public key ${key.id}`);
  }
  console.log(`Release keys OK (${RELEASE_KEYS.length})`);
});
