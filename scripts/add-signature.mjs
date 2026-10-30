import fs from 'node:fs';
import path from 'node:path';
import { verifySignatures } from '../dist/release-verify.js';
import { RELEASE_KEYS } from '../dist/release-keys.js';
import {
  args, required, base64, testKeyOptions, verificationKeys, main,
} from './lib/release-cli.mjs';

main(async () => {
  const values = args({
    dir: { type: 'string' },
    'key-id': { type: 'string' },
    sig: { type: 'string' },
    ...testKeyOptions,
  });
  required(values, ['dir', 'key-id', 'sig']);
  base64(values.sig, 64, 'Signature');
  const keys = verificationKeys(values, RELEASE_KEYS);
  const record = fs.readFileSync(path.join(values.dir, 'release.json'));
  const signaturesPath = path.join(values.dir, 'release.json.sigs');
  let signatures = [];
  try {
    signatures = JSON.parse(fs.readFileSync(signaturesPath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (!Array.isArray(signatures)) throw new Error('release.json.sigs must be a JSON array');
  const ids = new Set();
  for (const signature of signatures) {
    if (!signature || typeof signature.key_id !== 'string' || typeof signature.sig !== 'string' ||
        Object.keys(signature).length !== 2) {
      throw new Error('Invalid signature entry');
    }
    base64(signature.sig, 64, 'Signature');
    if (ids.has(signature.key_id)) throw new Error(`Duplicate key_id: ${signature.key_id}`);
    ids.add(signature.key_id);
  }
  if (ids.has(values['key-id'])) throw new Error(`Duplicate key_id: ${values['key-id']}`);
  signatures.push({ key_id: values['key-id'], sig: values.sig });
  // The NEW signature must verify on its own, by the key it names. Checking the whole list would
  // pass a bad signature appended next to a good one (verifySignatures accepts if ANY verifies).
  const alone = verifySignatures(record, Buffer.from(JSON.stringify([signatures[signatures.length - 1]])), keys);
  if (!alone.ok || alone.keyId !== values['key-id']) {
    throw new Error(`The new signature does not verify with key ${values['key-id']}${alone.ok ? '' : ` (${alone.reason})`}`);
  }
  const bytes = Buffer.from(JSON.stringify(signatures));
  const result = verifySignatures(record, bytes, keys);
  if (!result.ok) throw new Error(`Release signatures do not verify (${result.reason})`);
  fs.writeFileSync(signaturesPath, bytes);
  console.log(signaturesPath);
});
