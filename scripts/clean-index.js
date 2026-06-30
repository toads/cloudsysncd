#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

function resolveDataDir() {
  if (process.env.DATA_DIR) return path.resolve(process.env.DATA_DIR);
  const localDir = path.join(__dirname, '..', 'data');
  const dockerDir = path.join(__dirname, '..', '.local', 'data');
  if (fs.existsSync(path.join(dockerDir, '.admin-token'))) return dockerDir;
  return localDir;
}

const dataDir = resolveDataDir();
const indexFile = path.join(dataDir, 'storage-index.json');

if (!fs.existsSync(indexFile)) {
  console.log('No storage index found.');
  process.exit(0);
}

const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
const files = Object.keys(index.files || {});

if (files.length === 0) {
  console.log('Index is already empty.');
  process.exit(0);
}

console.log(`Found ${files.length} entries in storage index:`);
for (const relPath of files) {
  console.log(`  - ${relPath}`);
}

index.files = {};
fs.writeFileSync(indexFile, JSON.stringify(index, null, 2));
console.log(`\nCleared ${files.length} entries from storage index.`);
console.log('Cloud storage references removed. All downloads will now use local streaming.');
