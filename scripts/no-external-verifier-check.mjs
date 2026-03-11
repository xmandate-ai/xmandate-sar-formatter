#!/usr/bin/env node
// Guard script: scans repo text files for forbidden external verifier references.
// Exits non-zero if any are found. Run via: npm run check:no-external-verifier
//
// Forbidden strings are constructed at runtime so this script does not flag itself.

import { readFileSync, readdirSync } from 'node:fs';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DV = ['default', 'verifier'].join('');
const FORBIDDEN = [
  `${DV}.com`,
  DV,
  ['Default Settlement', 'V' + 'erifier'].join(' '),
];

const SELF = fileURLToPath(import.meta.url);

const TEXT_EXTS = new Set([
  '.ts', '.js', '.mjs', '.cjs', '.json', '.md', '.txt', '.yml', '.yaml', '.toml',
]);

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git']);

function walk(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walk(full));
    } else if (TEXT_EXTS.has(extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

let found = false;
for (const file of walk('.')) {
  // Skip this script itself — it contains the patterns as runtime-constructed constants.
  if (file === SELF) continue;
  const content = readFileSync(file, 'utf-8');
  for (const term of FORBIDDEN) {
    if (content.includes(term)) {
      console.error(`FORBIDDEN: "${term}" found in ${file}`);
      found = true;
    }
  }
}

if (found) {
  process.exit(1);
} else {
  console.log('No external verifier references found.');
}
