import fs from 'node:fs';
import { args, required, base64, main } from './lib/release-cli.mjs';

main(() => {
  const values = args({
    pub: { type: 'string' },
    id: { type: 'string' },
  });
  required(values, ['pub', 'id']);
  base64(values.pub, 32, 'Test public key');
  const source = `// TEST BUILD — never release
export interface ReleaseKey {
  id: string;
  publicKey: string;
  test?: boolean;
}

export const RELEASE_KEYS: ReleaseKey[] = [
  { id: ${JSON.stringify(values.id)}, publicKey: ${JSON.stringify(values.pub)}, test: true },
];
`;
  const target = new URL('../src/release-keys.ts', import.meta.url);
  fs.writeFileSync(target, source);
  console.log('Installed TEST release key in src/release-keys.ts; rebuild before testing. Never publish this build.');
});
