#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

function resolveSharedDir() {
  if (process.env.SHARED_DIR) {
    return path.resolve(process.env.SHARED_DIR);
  }

  const localDir = path.join(__dirname, 'shared');
  const dockerDir = path.join(__dirname, '.local', 'shared');
  const dockerToken = path.join(__dirname, '.local', 'data', '.admin-token');

  if (fs.existsSync(dockerToken)) {
    return dockerDir;
  }
  return localDir;
}

const sharedDir = resolveSharedDir();
const repoSharedSourceDir = path.resolve(path.join(__dirname, 'shared'));
const INTERNAL_SHARED_RELATIVE_PATHS = new Set(
  sharedDir === repoSharedSourceDir ? ['sync_download.py'] : []
);

function isInternalSharedRelPath(relPath) {
  const normalized = String(relPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '');
  return INTERNAL_SHARED_RELATIVE_PATHS.has(normalized);
}

const args = process.argv.slice(2);

if (args.length === 0) {
  const displayDir = path.relative(process.cwd(), sharedDir) || '.';
  console.log('用法:');
  console.log(`  node share.js file1.pdf dir/ file2.txt  — 复制到 ${displayDir}/`);
  console.log('  node share.js --list                    — 列出共享文件');
  console.log(`  node share.js --clear                   — 清空 ${displayDir}/`);
  process.exit(0);
}

// --list: show current shared files
if (args[0] === '--list') {
  if (!fs.existsSync(sharedDir)) {
    console.log(`${path.relative(process.cwd(), sharedDir) || '.'}/ 目录为空`);
    process.exit(0);
  }
  const walk = (dir, prefix = '') => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      if (isInternalSharedRelPath(rel)) continue;
      if (e.isDirectory()) {
        walk(path.join(dir, e.name), rel);
      } else {
        const sz = fs.statSync(path.join(dir, e.name)).size;
        console.log(`  ${rel}  (${formatSize(sz)})`);
      }
    }
  };
  walk(sharedDir);
  process.exit(0);
}

// --clear: remove all files in shared/
if (args[0] === '--clear') {
  if (fs.existsSync(sharedDir)) {
    for (const entry of fs.readdirSync(sharedDir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      if (isInternalSharedRelPath(entry.name)) continue;
      fs.rmSync(path.join(sharedDir, entry.name), { recursive: true, force: true });
    }
  }
  fs.mkdirSync(sharedDir, { recursive: true });
  console.log(`${path.relative(process.cwd(), sharedDir) || '.'}/ 已清空`);
  process.exit(0);
}

// Copy files/dirs to shared/
fs.mkdirSync(sharedDir, { recursive: true });
let count = 0;

for (const src of args) {
  const resolved = path.resolve(src);
  if (!fs.existsSync(resolved)) {
    console.error(`  跳过: ${src} (不存在)`);
    continue;
  }
  const stat = fs.statSync(resolved);
  const dest = path.join(sharedDir, path.basename(resolved));

  if (stat.isDirectory()) {
    fs.cpSync(resolved, dest, { recursive: true });
  } else {
    fs.copyFileSync(resolved, dest);
  }
  console.log(`  + ${path.basename(resolved)}`);
  count++;
}

console.log(`共复制 ${count} 项到 ${path.relative(process.cwd(), sharedDir) || '.'}/`);

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
