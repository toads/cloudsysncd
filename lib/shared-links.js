'use strict';
// 已登记软链接白名单(data/shared-links.json)的读写与判断工具
// share.js --link 写入(原子写),server.js 读取(带 mtime 缓存)
const fs = require('fs');
const path = require('path');

const REGISTRY_FILE_NAME = 'shared-links.json';

function getRegistryPath(dataDir) {
  return path.join(dataDir, REGISTRY_FILE_NAME);
}

// 链接名只允许 sharedDir 顶层的 basename,不得含路径分隔符
function isValidLinkName(name) {
  if (typeof name !== 'string' || !name) return false;
  if (name === '.' || name === '..') return false;
  if (name.includes('/') || name.includes('\\')) return false;
  return true;
}

// 路径比较跨平台规范化:win32 下统一转小写(调用方需先走 realpath 再比较)
function normalizePathForCompare(candidate) {
  if (typeof candidate !== 'string') return '';
  return process.platform === 'win32' ? candidate.toLowerCase() : candidate;
}

// 过滤非法条目:链接名必须是顶层 basename,目标必须是绝对路径 realpath
function sanitizeRegistry(raw) {
  const registry = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return registry;
  for (const [name, target] of Object.entries(raw)) {
    if (!isValidLinkName(name)) continue;
    if (typeof target !== 'string' || !path.isAbsolute(target)) continue;
    registry[name] = target;
  }
  return registry;
}

// 读取登记文件;文件缺失或损坏时视为空登记
function loadRegistry(dataDir) {
  try {
    const filePath = getRegistryPath(dataDir);
    if (!fs.existsSync(filePath)) return {};
    return sanitizeRegistry(JSON.parse(fs.readFileSync(filePath, 'utf8')));
  } catch {
    return {};
  }
}

// 原子写:临时文件 + rename
function saveRegistryAtomic(dataDir, registry) {
  fs.mkdirSync(dataDir, { recursive: true });
  const filePath = getRegistryPath(dataDir);
  const tempPath = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(tempPath, JSON.stringify(sanitizeRegistry(registry), null, 2));
  fs.renameSync(tempPath, filePath);
}

// server.js 用:带 mtime 缓存的登记读取器,文件变化时自动重载
function createCachedRegistryReader(dataDir) {
  const filePath = getRegistryPath(dataDir);
  let cachedMtimeMs = -1;
  let cachedRegistry = {};
  return function readRegistry() {
    let stat = null;
    try {
      stat = fs.statSync(filePath);
    } catch {
      stat = null;
    }
    if (!stat) {
      if (cachedMtimeMs !== 0) {
        cachedMtimeMs = 0;
        cachedRegistry = {};
      }
      return cachedRegistry;
    }
    if (stat.mtimeMs !== cachedMtimeMs) {
      cachedMtimeMs = stat.mtimeMs;
      cachedRegistry = loadRegistry(dataDir);
    }
    return cachedRegistry;
  };
}

// 按顶层名字查登记目标(win32 下名字比较不区分大小写)
function getRegisteredTarget(registry, name) {
  if (!isValidLinkName(name) || !registry) return null;
  if (Object.prototype.hasOwnProperty.call(registry, name)) return registry[name];
  if (process.platform === 'win32') {
    const lower = name.toLowerCase();
    for (const [key, target] of Object.entries(registry)) {
      if (key.toLowerCase() === lower) return target;
    }
  }
  return null;
}

// 判断某个 realpath 是否等于登记目标或位于其内部(目录链接的子路径要允许)
function isRealPathWithinTarget(realPath, target) {
  if (!realPath || !target) return false;
  const from = normalizePathForCompare(path.resolve(target));
  const to = normalizePathForCompare(path.resolve(realPath));
  if (from === to) return true;
  const relative = path.relative(from, to);
  return !!relative && !relative.startsWith('..') && !path.isAbsolute(relative);
}

module.exports = {
  REGISTRY_FILE_NAME,
  getRegistryPath,
  isValidLinkName,
  normalizePathForCompare,
  sanitizeRegistry,
  loadRegistry,
  saveRegistryAtomic,
  createCachedRegistryReader,
  getRegisteredTarget,
  isRealPathWithinTarget,
};
