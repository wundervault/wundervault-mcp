import fs from 'node:fs';
import path from 'node:path';

export function checkClosure(root) {
  function visit(file) {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink()) throw new Error(`Symlink refused: ${file}`);
    if (stat.isDirectory()) {
      for (const name of fs.readdirSync(file).sort()) visit(path.join(file, name));
      return;
    }
    if (!stat.isFile()) throw new Error(`Non-file refused: ${file}`);
    if (file.toLowerCase().endsWith('.node')) throw new Error(`Native module refused: ${file}`);
    if (path.basename(file) !== 'package.json') return;
    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      throw new Error(`Invalid package.json: ${file}`);
    }
    if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
      throw new Error(`Invalid package.json: ${file}`);
    }
    for (const field of ['os', 'cpu']) {
      if (Object.hasOwn(pkg, field)) throw new Error(`${field} restriction refused: ${file}`);
    }
    for (const script of ['preinstall', 'install', 'postinstall']) {
      if (pkg.scripts && Object.hasOwn(pkg.scripts, script)) {
        throw new Error(`${script} script refused: ${file}`);
      }
    }
  }
  visit(root);
}
