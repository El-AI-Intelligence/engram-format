#!/usr/bin/env node
// Merge npm metadata from ./package.json into wasm-pack's generated
// pkg/package.json. wasm-pack copies name/version/license from Cargo.toml
// but not description/repository/keywords, and it copies the crate's
// Rust-facing README; this script fills the npm-facing gaps.
const fs = require('fs');

const meta = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const pkgPath = 'pkg/package.json';
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

for (const key of ['description', 'repository', 'keywords', 'author', 'homepage', 'bugs']) {
  if (meta[key] !== undefined) pkg[key] = meta[key];
}

// JS-facing README for the npm page (wasm-pack copies the crate README.md,
// which is aimed at Rust users).
const readmePath = 'README.md';
if (fs.existsSync(readmePath)) {
  fs.copyFileSync(readmePath, 'pkg/README.md');
}

fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
console.log('Merged npm metadata into', pkgPath);
