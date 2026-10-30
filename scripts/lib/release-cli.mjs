import { parseArgs } from 'node:util';

export function args(options) {
  return parseArgs({ options, allowPositionals: false, strict: true }).values;
}

export function required(values, names) {
  for (const name of names) {
    if (typeof values[name] !== 'string' || !values[name]) {
      throw new Error(`Missing --${name}`);
    }
  }
}

export function base64(value, bytes, label) {
  if (typeof value !== 'string' ||
      Buffer.from(value, 'base64').toString('base64') !== value ||
      Buffer.from(value, 'base64').length !== bytes) {
    throw new Error(`${label} must be canonical base64 of ${bytes} bytes`);
  }
  return value;
}

export const testKeyOptions = {
  'test-key': { type: 'string' },
  'test-key-id': { type: 'string' },
};

export function verificationKeys(values, installedKeys) {
  const pub = values['test-key'];
  const id = values['test-key-id'];
  if (pub === undefined && id === undefined) return installedKeys;
  if (!pub || !id) throw new Error('--test-key and --test-key-id must be supplied together');
  base64(pub, 32, 'Test public key');
  return [{ id, publicKey: pub, test: true }];
}

export function main(fn) {
  Promise.resolve().then(fn).catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
