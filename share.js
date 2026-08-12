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

function resolveDataDir() {
  if (process.env.DATA_DIR) {
    return path.resolve(process.env.DATA_DIR);
  }

  const localDir = path.join(__dirname, 'data');
  const dockerDir = path.join(__dirname, '.local', 'data');
  const dockerToken = path.join(__dirname, '.local', 'data', '.admin-token');

  if (fs.existsSync(dockerToken)) {
    return dockerDir;
  }
  return localDir;
}

const sharedDir = resolveSharedDir();
const dataDir = resolveDataDir();
const repoSharedSourceDir = path.resolve(path.join(__dirname, 'shared'));

const storage = require('./lib/cloud-storage');
const sharedLinks = require('./lib/shared-links');

function loadMasterKey() {
  try {
    const stateFile = path.join(dataDir, 'state.json');
    if (!fs.existsSync(stateFile)) return null;
    const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    if (state && typeof state.masterKey === 'string' && state.masterKey) {
      return Buffer.from(state.masterKey, 'hex');
    }
  } catch {
    return null;
  }
}

function walkSharedFiles(dir, prefix = '') {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (isHiddenSharedRelPath(rel)) continue;
    const full = path.join(dir, entry.name);
    let stat;
    try {
      stat = fs.lstatSync(full);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) {
      console.warn(`  跳过符号链接: ${rel}`);
      continue;
    }
    if (entry.isDirectory()) {
      results.push(...walkSharedFiles(full, rel));
    } else {
      results.push({ rel, full });
    }
  }
  return results;
}

function scheduleCloudUpload(relPath, fullPath) {
  const masterKey = loadMasterKey();
  if (!masterKey) return;
  if (!storage.isStorageEnabled()) return;
  storage.uploadFileToCloud(dataDir, masterKey, relPath, fullPath).catch(() => {});
}

function scheduleCloudClear() {
  if (!storage.isStorageEnabled()) return;
  const index = storage.loadIndex ? storage.loadIndex(dataDir) : { files: {} };
  const entries = Object.keys(index.files || {});
  for (const relPath of entries) {
    storage.deleteCloudObjectForPath(dataDir, relPath).catch(() => {});
  }
}
const HIDDEN_SHARED_RELATIVE_PATHS = new Set(
  sharedDir === repoSharedSourceDir ? ['sync_download.py', '__pycache__'] : []
);
const PROTECTED_SHARED_RELATIVE_PATHS = new Set(
  sharedDir === repoSharedSourceDir ? ['sync_download.py'] : []
);

function normalizeSharedRelPath(relPath) {
  return String(relPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '');
}

function matchesSharedRelPath(relPath, protectedPaths) {
  const normalized = normalizeSharedRelPath(relPath);
  for (const entry of protectedPaths) {
    if (normalized === entry || normalized.startsWith(`${entry}/`)) {
      return true;
    }
  }
  return false;
}

function isHiddenSharedRelPath(relPath) {
  return matchesSharedRelPath(relPath, HIDDEN_SHARED_RELATIVE_PATHS);
}

function isProtectedSharedRelPath(relPath) {
  return matchesSharedRelPath(relPath, PROTECTED_SHARED_RELATIVE_PATHS);
}

function isInternalSharedRelPath(relPath) {
  const normalized = String(relPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '');
  return isHiddenSharedRelPath(normalized);
}

const args = process.argv.slice(2);

if (args.length === 0) {
  const displayDir = path.relative(process.cwd(), sharedDir) || '.';
  console.log('用法:');
  console.log(`  node share.js file1.pdf dir/ file2.txt  — 复制到 ${displayDir}/`);
  console.log(`  node share.js --link file1 dir/ ...     — 以符号链接挂到 ${displayDir}/(不复制、不上传云端)`);
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
  const registry = sharedLinks.loadRegistry(dataDir);
  const walk = (dir, prefix = '') => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      if (isHiddenSharedRelPath(rel)) continue;
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) {
        // 顶层已登记链接正常显示并跟随,其余符号链接保持跳过
        const target = prefix === '' ? sharedLinks.getRegisteredTarget(registry, e.name) : null;
        if (!target) {
          console.warn(`  跳过符号链接: ${rel}`);
          continue;
        }
        let linkStat = null;
        try {
          linkStat = fs.statSync(full);
        } catch {
          linkStat = null;
        }
        if (linkStat && linkStat.isDirectory()) {
          console.log(`  ${rel} -> ${target} (链接)`);
          walk(full, rel);
        } else if (linkStat && linkStat.isFile()) {
          console.log(`  ${rel} -> ${target} (链接, ${formatSize(linkStat.size)})`);
        } else {
          console.log(`  ${rel} -> ${target} (链接, 目标缺失)`);
        }
        continue;
      }
      if (e.isDirectory()) {
        walk(full, rel);
      } else {
        const sz = fs.statSync(full).size;
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
      if (isProtectedSharedRelPath(entry.name)) continue;
      // rmSync 作用于符号链接本身,不会跟随删除目标
      fs.rmSync(path.join(sharedDir, entry.name), { recursive: true, force: true });
    }
  }
  fs.mkdirSync(sharedDir, { recursive: true });
  // 同步清空软链接登记文件
  sharedLinks.saveRegistryAtomic(dataDir, {});
  scheduleCloudClear();
  console.log(`${path.relative(process.cwd(), sharedDir) || '.'}/ 已清空`);
  process.exit(0);
}

// --link: symlink external files/dirs into shared/ and register them
if (args[0] === '--link') {
  const sources = args.slice(1);
  if (sources.length === 0) {
    console.error('用法: node share.js --link <文件或目录> [更多路径...]');
    process.exit(1);
  }
  fs.mkdirSync(sharedDir, { recursive: true });
  const registry = sharedLinks.loadRegistry(dataDir);
  let count = 0;
  let failed = false;

  for (const src of sources) {
    const resolved = path.resolve(src);
    if (!fs.existsSync(resolved)) {
      console.error(`  跳过: ${src} (不存在)`);
      continue;
    }
    const stat = fs.lstatSync(resolved);
    if (stat.isSymbolicLink()) {
      console.error(`  跳过: ${src} (源本身是符号链接,不允许共享)`);
      continue;
    }
    const realTarget = fs.realpathSync(resolved);
    const baseName = path.basename(resolved);
    const dest = path.join(sharedDir, baseName);

    let existing = null;
    try {
      existing = fs.lstatSync(dest);
    } catch {
      existing = null;
    }
    if (existing) {
      console.error(`  跳过: ${baseName} (共享目录中已存在同名条目)`);
      continue;
    }

    const isDir = stat.isDirectory();
    // Windows 目录用 junction(无需管理员权限,要求绝对路径),文件用默认 symlink
    const linkType = process.platform === 'win32'
      ? (isDir ? 'junction' : 'file')
      : (isDir ? 'dir' : 'file');
    try {
      fs.symlinkSync(realTarget, dest, linkType);
    } catch (err) {
      failed = true;
      if (err && ['EPERM', 'EACCES', 'ENOTSUP'].includes(err.code)) {
        console.error(`  失败: ${baseName} (创建符号链接被拒绝: ${err.code})`);
        if (process.platform === 'win32' && !isDir) {
          console.error('  提示: Windows 创建文件符号链接需要管理员权限或开发者模式,可改用复制模式: node share.js <文件>');
        } else {
          console.error('  提示: 当前环境不允许创建符号链接,可改用复制模式: node share.js <路径>');
        }
      } else {
        console.error(`  失败: ${baseName} (${err && err.message ? err.message : err})`);
      }
      continue;
    }

    registry[baseName] = realTarget;
    console.log(`  + ${baseName} -> ${realTarget} (链接)`);
    count++;
  }

  if (count > 0) {
    sharedLinks.saveRegistryAtomic(dataDir, registry);
  }
  console.log(`共创建 ${count} 个链接到 ${path.relative(process.cwd(), sharedDir) || '.'}/(链接项不调度云上传)`);
  process.exit(failed ? 1 : 0);
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
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink()) {
    console.error(`  跳过: ${src} (符号链接不允许共享)`);
    continue;
  }
  const dest = path.join(sharedDir, path.basename(resolved));

  if (stat.isDirectory()) {
    fs.cpSync(resolved, dest, {
      recursive: true,
      dereference: false,
      filter: (source) => !fs.lstatSync(source).isSymbolicLink(),
    });
  } else {
    fs.copyFileSync(resolved, dest);
  }
  console.log(`  + ${path.basename(resolved)}`);
  count++;

  const baseName = path.basename(resolved);
  const scanRoot = stat.isDirectory() ? dest : path.join(sharedDir, baseName);
  const relPrefix = stat.isDirectory() ? baseName : '';
  const files = stat.isDirectory()
    ? walkSharedFiles(scanRoot, relPrefix)
    : [{ rel: baseName, full: scanRoot }];
  for (const { rel, full } of files) {
    scheduleCloudUpload(rel, full);
  }
}

console.log(`共复制 ${count} 项到 ${path.relative(process.cwd(), sharedDir) || '.'}/`);

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
