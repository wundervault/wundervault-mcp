import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { args, required, main } from './lib/release-cli.mjs';
import { collectTree, buildArchive } from './lib/ustar.mjs';
import { checkClosure } from './lib/closure-check.mjs';

main(() => {
  const values = args({ out: { type: 'string' } });
  required(values, ['out']);
  const root = process.cwd();
  const out = path.resolve(values.out);
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(pkg.version)) {
    throw new Error('package.json must have an X.Y.Z version');
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'wundervault-pack-'));
  try {
    for (const name of ['package.json', 'package-lock.json']) {
      const source = path.join(root, name);
      if (!fs.lstatSync(source).isFile()) throw new Error(`Regular file required: ${source}`);
      fs.copyFileSync(source, path.join(temp, name));
    }
    execFileSync('npm', ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], {
      cwd: temp,
      stdio: 'inherit',
    });
    const modules = path.join(temp, 'node_modules');
    fs.mkdirSync(modules, { recursive: true });
    fs.rmSync(path.join(modules, '.bin'), { recursive: true, force: true });
    checkClosure(modules);

    const entries = [{ path: 'app', directory: true }];
    for (const name of ['package.json', 'README.md', 'CHANGELOG.md', 'bin', 'dist', 'packaging']) {
      entries.push(...collectTree(path.join(root, name), `app/${name}`, (name, directory) =>
        directory || !name.startsWith('app/dist/') ||
        (!name.endsWith('.d.ts') && !name.endsWith('.d.ts.map'))));
    }
    entries.push(...collectTree(modules, 'app/node_modules'));
    const result = buildArchive(entries);
    fs.mkdirSync(out, { recursive: true });
    const archivePath = path.join(out, `wundervault-app-${pkg.version}.tar.gz`);
    const filesPath = path.join(out, 'app-files.json');
    fs.writeFileSync(archivePath, result.archive);
    fs.writeFileSync(filesPath, JSON.stringify({
      version: pkg.version,
      sha256: result.sha256,
      files: result.files,
    }));
    console.log(archivePath);
    console.log(filesPath);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
