const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream/promises');
const { NodeHttpHandler } = require('@smithy/node-http-handler');
const { S3Client, DeleteObjectCommand, HeadObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { GetObjectCommand } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const chunkedAead = require('./chunked-aead');

let cachedClient = null;
let cachedConfig = null;
let cleanupTimer = null;
let quotaCheckTimer = null;
let lastQuotaCheck = null;
let quotaExceeded = false;

async function checkQiniuQuota(cfg) {
  try {
    const { S3Client, ListObjectsV2Command, DeleteObjectCommand } = require('@aws-sdk/client-s3');
    const client = new S3Client({
      endpoint: cfg.endpoint,
      region: cfg.region,
      credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
      forcePathStyle: true,
    });

    const maxBytes = Math.max(0, Number.parseInt(process.env.QINIU_MAX_BYTES || '10737418240', 10) || 10737418240);

    let totalSize = 0;
    let allKeys = [];
    let continuationToken = null;

    do {
      const result = await client.send(new ListObjectsV2Command({
        Bucket: cfg.bucket,
        MaxKeys: 1000,
        ContinuationToken: continuationToken || undefined,
      }));

      for (const obj of result.Contents || []) {
        totalSize += obj.Size || 0;
        allKeys.push(obj.Key);
      }

      continuationToken = result.IsTruncated ? result.NextContinuationToken : null;
    } while (continuationToken);

    if (totalSize >= maxBytes) {
      console.error(`[Storage] Qiniu quota exceeded: ${formatBytes(totalSize)} / ${formatBytes(maxBytes)}. Purging all objects...`);

      for (const key of allKeys) {
        try {
          await client.send(new DeleteObjectCommand({ Bucket: cfg.bucket, Key: key }));
        } catch (delErr) {
          console.error(`[Storage] Failed to delete ${key}:`, delErr.message);
        }
      }

      console.error(`[Storage] Purged ${allKeys.length} objects. Cloud storage disabled to prevent charges.`);
      return { exceeded: true, used: 0, limit: maxBytes, purged: allKeys.length };
    }

    console.log(`[Storage] Qiniu quota check: ${formatBytes(totalSize)} / ${formatBytes(maxBytes)} (${((totalSize / maxBytes) * 100).toFixed(2)}%)`);
    return { exceeded: false, used: totalSize, limit: maxBytes };
  } catch (err) {
    console.error('[Storage] Qiniu quota check failed:', err.message);
    return { exceeded: false, used: 0, limit: 0, error: err.message };
  }
}

function formatBytes(bytes) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

function loadStorageConfig() {
  if (cachedConfig) return cachedConfig;

  const provider = (process.env.STORAGE_PROVIDER || (process.env.R2_ENABLED === 'true' ? 'r2' : '')).toLowerCase();
  if (!provider || provider === 'false') {
    cachedConfig = { enabled: false };
    return cachedConfig;
  }

  const cosRegion = process.env.COS_REGION || parseCosRegion(process.env.COS_ENDPOINT) || 'ap-shanghai';
  const configs = {
    r2: {
      endpoint: process.env.R2_ENDPOINT,
      accessKeyId: process.env.R2_ACCESS_KEY_ID,
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
      bucket: process.env.R2_BUCKET,
      region: process.env.R2_REGION || 'auto',
      forcePathStyle: true,
    },
    qiniu: {
      endpoint: process.env.QINIU_ENDPOINT || 'https://s3-cn-east-1.qiniucs.com',
      accessKeyId: process.env.QINIU_ACCESS_KEY,
      secretAccessKey: process.env.QINIU_SECRET_KEY,
      bucket: process.env.QINIU_BUCKET,
      region: process.env.QINIU_REGION || 'cn-east-1',
      forcePathStyle: true,
    },
    cos: {
      endpoint: normalizeCosEndpoint(process.env.COS_ENDPOINT, process.env.COS_BUCKET, cosRegion),
      accessKeyId: process.env.COS_SECRET_ID || process.env.TENCENTCLOUD_SECRET_ID || process.env.SecretId,
      secretAccessKey: process.env.COS_SECRET_KEY || process.env.TENCENTCLOUD_SECRET_KEY || process.env.SecretKey,
      bucket: process.env.COS_BUCKET,
      region: cosRegion,
      forcePathStyle: false,
    },
    hybrid: {
      endpoint: normalizeCosEndpoint(process.env.COS_ENDPOINT, process.env.COS_BUCKET, cosRegion),
      accessKeyId: process.env.COS_SECRET_ID || process.env.TENCENTCLOUD_SECRET_ID || process.env.SecretId,
      secretAccessKey: process.env.COS_SECRET_KEY || process.env.TENCENTCLOUD_SECRET_KEY || process.env.SecretKey,
      bucket: process.env.COS_BUCKET,
      region: cosRegion,
      forcePathStyle: false,
    },
    local: {
      endpoint: '',
      accessKeyId: '',
      secretAccessKey: '',
      bucket: '',
      region: 'local',
      forcePathStyle: true,
    },
  };

  const cfg = configs[provider];
  if (!cfg) {
    console.error(`[Storage] Unknown provider: ${provider}`);
    cachedConfig = { enabled: false };
    return cachedConfig;
  }

  const needsRemote = provider !== 'local' && provider !== 'hybrid';
  const remoteEnabled = !!(cfg.endpoint && cfg.accessKeyId && cfg.secretAccessKey && cfg.bucket);
  if (needsRemote && !remoteEnabled) {
    console.error(`[Storage] Provider ${provider} enabled but missing required credentials`);
    cachedConfig = { enabled: false };
    return cachedConfig;
  }

  if (provider === 'hybrid' && !remoteEnabled) {
    console.error('[Storage] Hybrid provider missing COS credentials; large files will remain on local disk');
  }

  const localLike = provider === 'local' || provider === 'hybrid';
  const fallbackDefault = localLike || provider === 'cos' ? '0' : '1048576';
  const maxDefault = localLike ? '10737418240' : '5368709120';

  cachedConfig = {
    enabled: true,
    provider,
    ...cfg,
    remoteEnabled,
    fallbackBytes: Math.max(0, Number.parseInt(process.env.STORAGE_FALLBACK_BYTES || process.env.R2_FALLBACK_BYTES || fallbackDefault, 10) || 0),
    remoteThresholdBytes: Math.max(64 * 1024, Number.parseInt(process.env.STORAGE_REMOTE_THRESHOLD_BYTES || process.env.COS_THRESHOLD_BYTES || String(64 * 1024 * 1024), 10) || 64 * 1024 * 1024),
    presignExpirySeconds: Math.max(60, Number.parseInt(process.env.STORAGE_PRESIGN_EXPIRY_SECONDS || process.env.R2_PRESIGN_EXPIRY_SECONDS || '3600', 10) || 3600),
    hotDurationMs: Math.max(3600000, Number.parseInt(process.env.STORAGE_HOT_DURATION_MS || '259200000', 10) || 259200000),
    maxStorageBytes: Math.max(0, Number.parseInt(process.env.STORAGE_MAX_BYTES || process.env.STORAGE_LOCAL_MAX_BYTES || maxDefault, 10) || Number.parseInt(maxDefault, 10)),
    remoteMaxBytes: Math.max(0, Number.parseInt(process.env.STORAGE_REMOTE_MAX_BYTES || '0', 10) || 0),
    cleanupIntervalMs: Math.max(300000, Number.parseInt(process.env.STORAGE_CLEANUP_INTERVAL_MS || '3600000', 10) || 3600000),
    downloadMode: (process.env.STORAGE_DOWNLOAD_MODE || (localLike || provider === 'cos' ? 'proxy' : 'redirect')).toLowerCase(),
    localDir: process.env.STORAGE_LOCAL_DIR || '',
    aeadChunkBytes: parseByteEnv('STORAGE_AEAD_CHUNK_BYTES', chunkedAead.DEFAULT_CHUNK_SIZE, 256 * 1024, 16 * 1024 * 1024),
    remotePartBytes: parseByteEnv('STORAGE_REMOTE_PART_BYTES', 8 * 1024 * 1024, 5 * 1024 * 1024, 512 * 1024 * 1024),
    requestTimeoutMs: parseByteEnv('STORAGE_REQUEST_TIMEOUT_MS', 120000, 5000, 30 * 60 * 1000),
    cdnEndpoint: process.env.QINIU_CDN_ENDPOINT || '',
    cdnBucket: process.env.QINIU_CDN_BUCKET || '',
  };
  return cachedConfig;
}

function parseByteEnv(name, fallback, min, max) {
  const value = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

function parseCosRegion(endpoint) {
  if (!endpoint) return '';
  const match = String(endpoint).match(/\.cos\.([a-z0-9-]+)\.myqcloud\.com/i)
    || String(endpoint).match(/^https?:\/\/cos\.([a-z0-9-]+)\.myqcloud\.com/i);
  return match ? match[1] : '';
}

function normalizeCosEndpoint(endpoint, bucket, region) {
  const raw = String(endpoint || '').trim();
  if (!raw) return `https://cos.${region}.myqcloud.com`;
  if (bucket && raw.includes(`${bucket}.cos.`)) {
    return `https://cos.${region || parseCosRegion(raw)}.myqcloud.com`;
  }
  return raw.replace(/\/+$/, '');
}

function getS3Client() {
  if (cachedClient) return cachedClient;
  const config = loadStorageConfig();
  if (!config.enabled || !config.remoteEnabled) return null;
  cachedClient = new S3Client({
    region: config.region,
    endpoint: config.endpoint,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
    forcePathStyle: config.forcePathStyle !== false,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: Math.min(10000, config.requestTimeoutMs),
      requestTimeout: config.requestTimeoutMs,
    }),
  });
  return cachedClient;
}

function makeObjectKey(relPath) {
  const hash = crypto.createHash('sha256').update(relPath).digest('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  return `syncd/encrypted/${nonce}-${hash.slice(0, 16)}`;
}

function getIndexFilePath(dataDir) {
  return path.join(dataDir, 'storage-index.json');
}

function getLocalStoreDir(dataDir) {
  const config = loadStorageConfig();
  return path.resolve(config.localDir || path.join(dataDir, 'object-cache'));
}

function getLocalObjectPath(dataDir, objectKey) {
  const baseDir = getLocalStoreDir(dataDir);
  const normalized = String(objectKey || '').replace(/\\/g, '/').replace(/^\/+/, '');
  const fullPath = path.resolve(path.join(baseDir, normalized));
  if (fullPath !== baseDir && !fullPath.startsWith(baseDir + path.sep)) {
    throw new Error('Invalid local object key');
  }
  return fullPath;
}

function isPathInside(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === '' || (!!relative && !relative.startsWith('..') && !path.isAbsolute(relative));
}

function loadIndex(dataDir) {
  const file = getIndexFilePath(dataDir);
  try {
    if (fs.existsSync(file)) {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (parsed && typeof parsed === 'object' && parsed.files && typeof parsed.files === 'object') {
        return parsed;
      }
    }
  } catch (err) {
    console.error('[Storage] Failed to load index:', err.message);
  }
  return { version: 1, files: {} };
}

function saveIndex(dataDir, index) {
  const file = getIndexFilePath(dataDir);
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dataDir, 0o700); } catch {}
  fs.writeFileSync(file, JSON.stringify(index, null, 2), { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch {}
}

function getTotalStorageBytes(index) {
  return Object.values(index.files || {}).reduce((sum, entry) => sum + (entry.size || 0), 0);
}

function getStorageBytes(index, backend) {
  return Object.values(index.files || {})
    .filter((entry) => (entry.backend || 'remote') === backend)
    .reduce((sum, entry) => sum + (entry.size || 0), 0);
}

function createFileSignature(stat) {
  return `${stat.size}:${Math.trunc(Number(stat.mtimeMs) || 0)}`;
}

function isIndexEntryFresh(entry, stat) {
  if (!entry || !stat) return false;
  if (Number(entry.size) !== stat.size) return false;
  if (entry.fileSig) return entry.fileSig === createFileSignature(stat);
  if (entry.mtimeMs !== undefined) return Math.trunc(Number(entry.mtimeMs) || 0) === Math.trunc(Number(stat.mtimeMs) || 0);
  return false;
}

async function checkQuotaIfNeeded(dataDir) {
  const config = loadStorageConfig();
  if (!config.enabled || config.provider !== 'qiniu') return { exceeded: false };

  const now = Date.now();
  if (lastQuotaCheck && (now - lastQuotaCheck) < 60000) {
    return { exceeded: quotaExceeded };
  }

  lastQuotaCheck = now;
  const result = await checkQiniuQuota(config);
  quotaExceeded = result.exceeded;

  if (quotaExceeded && dataDir) {
    const index = loadIndex(dataDir);
    if (Object.keys(index.files || {}).length > 0) {
      index.files = {};
      saveIndex(dataDir, index);
      console.log('[Storage] Local index cleared after quota purge');
    }
  }

  return result;
}

function isStorageEnabled() {
  const config = loadStorageConfig();
  if (!config.enabled) return false;
  if (config.provider === 'qiniu' && quotaExceeded) {
    console.log('[Storage] Qiniu quota exceeded, temporarily disabled');
    return false;
  }
  return true;
}

function getProvider() {
  return loadStorageConfig().provider;
}

async function uploadFileToCloud(dataDir, masterKey, relPath, fullPath) {
  const config = loadStorageConfig();
  if (!config.enabled) return null;

  if (config.provider === 'qiniu') {
    const quotaResult = await checkQuotaIfNeeded(dataDir);
    if (quotaResult.exceeded) {
      console.error(`[Storage] Qiniu quota exceeded (${formatBytes(quotaResult.used)} / ${formatBytes(quotaResult.limit)}), skipping upload`);
      return null;
    }
  }

  const stat = fs.statSync(fullPath);
  const fileSize = stat.size;
  const backend = chooseBackend(config, fileSize);

  const index = loadIndex(dataDir);
  const oldEntry = index.files[relPath] || null;
  const oldBackend = oldEntry ? (oldEntry.backend || 'remote') : null;
  const oldSize = oldEntry ? (Number(oldEntry.size) || 0) : 0;
  const localBytesAfterReplacement = getStorageBytes(index, 'local') - (oldBackend === 'local' ? oldSize : 0);
  const remoteBytesAfterReplacement = getStorageBytes(index, 'remote') - (oldBackend === 'remote' ? oldSize : 0);

  if (backend === 'local' && localBytesAfterReplacement + fileSize > config.maxStorageBytes) {
    console.error(`[Storage] Upload would exceed maxStorageBytes (${config.maxStorageBytes}), skipping ${relPath}`);
    return null;
  }
  if (backend === 'remote' && config.remoteMaxBytes > 0 && remoteBytesAfterReplacement + fileSize > config.remoteMaxBytes) {
    console.error(`[Storage] Upload would exceed remoteMaxBytes (${config.remoteMaxBytes}), skipping ${relPath}`);
    return null;
  }

  const objectKey = makeObjectKey(relPath);
  const fileStream = fs.createReadStream(fullPath);
  const { stream: encryptedStream, ivBaseHex } = chunkedAead.createChunkedAeadStream(fileStream, masterKey, config.aeadChunkBytes);

  try {
    const result = backend === 'local'
      ? await uploadToLocalStore(dataDir, objectKey, encryptedStream)
      : await uploadToRemoteStore(config, objectKey, relPath, encryptedStream);

    index.files[relPath] = {
      objectKey,
      backend,
      provider: backend === 'local' ? 'local' : config.provider,
      ivBase: ivBaseHex,
      format: 'chunked-aead-v1',
      size: fileSize,
      mtimeMs: stat.mtimeMs,
      fileSig: createFileSignature(stat),
      encryptedSize: result.encryptedSize || null,
      etag: result.ETag || null,
      uploadedAt: new Date().toISOString(),
      lastAccessedAt: new Date().toISOString(),
    };
    saveIndex(dataDir, index);
    if (oldEntry && oldEntry.objectKey && oldEntry.objectKey !== objectKey) {
      try {
        await deleteStorageObject(dataDir, config, oldEntry);
      } catch (deleteErr) {
        console.error(`[Storage] Failed to delete replaced object for ${relPath}:`, deleteErr.message);
      }
    }
    console.log(`[Storage] Uploaded ${relPath} (${fileSize} bytes) -> ${backend}:${objectKey}`);
    return index.files[relPath];
  } catch (err) {
    console.error(`[Storage] Failed to upload ${relPath}:`, err.message);
    return null;
  }
}

function chooseBackend(config, fileSize) {
  if (config.provider === 'local') return 'local';
  if (config.provider === 'hybrid') {
    if (config.remoteEnabled && fileSize >= config.remoteThresholdBytes) return 'remote';
    return 'local';
  }
  return 'remote';
}

async function uploadToLocalStore(dataDir, objectKey, encryptedStream) {
  const target = getLocalObjectPath(dataDir, objectKey);
  const temp = `${target}.${process.pid}.${Date.now()}.tmp`;
  fs.mkdirSync(path.dirname(target), { recursive: true });
  await pipeline(encryptedStream, fs.createWriteStream(temp, { mode: 0o600 }));
  const stat = fs.statSync(temp);
  fs.renameSync(temp, target);
  return { ETag: null, encryptedSize: stat.size };
}

async function uploadToRemoteStore(config, objectKey, relPath, encryptedStream) {
  const client = getS3Client();
  if (!client) throw new Error('Remote storage credentials are not configured');

  const uploader = new Upload({
    client,
    params: {
      Bucket: config.bucket,
      Key: objectKey,
      Body: encryptedStream,
      Metadata: {
        'syncd-relpath': encodeURIComponent(relPath),
        'syncd-format': 'chunked-aead-v1',
      },
    },
    queueSize: 4,
    partSize: config.remotePartBytes,
    leavePartsOnError: false,
  });

  return uploader.done();
}

async function getCloudRedirectInfo(dataDir, relPath, fullPath) {
  const config = loadStorageConfig();
  if (!config.enabled) return null;

  if (config.provider === 'qiniu') {
    const quotaResult = await checkQuotaIfNeeded(dataDir);
    if (quotaResult.exceeded) {
      console.error(`[Storage] Qiniu quota exceeded (${formatBytes(quotaResult.used)} / ${formatBytes(quotaResult.limit)}), serving locally`);
      return null;
    }
  }

  const stat = fs.statSync(fullPath);
  if (stat.size < config.fallbackBytes) return null;

  const index = loadIndex(dataDir);
  const entry = index.files[relPath];
  if (!entry || !entry.objectKey) return null;
  if (!isIndexEntryFresh(entry, stat)) {
    console.log(`[Storage] Cached object is stale for ${relPath}, serving source file`);
    return null;
  }
  const backend = entry.backend || 'remote';

  try {
    if (backend === 'local') {
      if (!fs.existsSync(getLocalObjectPath(dataDir, entry.objectKey))) {
        throw new Error('Local object missing');
      }
    } else {
      const client = getS3Client();
      if (!client) throw new Error('Remote storage credentials are not configured');
      await client.send(new HeadObjectCommand({
        Bucket: config.bucket,
        Key: entry.objectKey,
      }));
    }
  } catch (err) {
    console.error(`[Storage] Object missing or inaccessible for ${relPath}:`, err.message);
    return null;
  }

  entry.lastAccessedAt = new Date().toISOString();
  saveIndex(dataDir, index);

  const cdnBase = config.cdnEndpoint || null;
  if (backend === 'local' || config.downloadMode === 'proxy') {
    return {
      proxy: true,
      backend,
      ivBase: entry.ivBase || null,
      format: entry.format || 'legacy',
      size: entry.size,
      objectKey: entry.objectKey,
    };
  }

  const client = getS3Client();
  const command = new GetObjectCommand({
    Bucket: config.bucket,
    Key: entry.objectKey,
  });
  const url = await getSignedUrl(client, command, { expiresIn: config.presignExpirySeconds });

  return {
    url: cdnBase ? `${cdnBase.replace(/\/+$/, '')}/${entry.objectKey}` : url,
    backend,
    ivBase: entry.ivBase || null,
    format: entry.format || 'legacy',
    size: entry.size,
    objectKey: entry.objectKey,
  };
}

async function deleteStorageObject(dataDir, config, entry) {
  const backend = entry.backend || 'remote';
  if (backend === 'local') {
    fs.rmSync(getLocalObjectPath(dataDir, entry.objectKey), { force: true });
    return;
  }

  const client = getS3Client();
  if (!client) throw new Error('Remote storage credentials are not configured');
  await client.send(new DeleteObjectCommand({
    Bucket: config.bucket,
    Key: entry.objectKey,
  }));
}

async function deleteCloudObjectForPath(dataDir, relPath) {
  const config = loadStorageConfig();
  if (!config.enabled) return false;
  const index = loadIndex(dataDir);
  const entry = index.files[relPath];
  if (!entry || !entry.objectKey) return false;
  const backend = entry.backend || 'remote';

  try {
    await deleteStorageObject(dataDir, config, entry);
    delete index.files[relPath];
    saveIndex(dataDir, index);
    console.log(`[Storage] Deleted ${relPath} -> ${backend}:${entry.objectKey}`);
    return true;
  } catch (err) {
    console.error(`[Storage] Failed to delete ${relPath}:`, err.message);
    return false;
  }
}

async function createCloudReadStream(dataDir, cloudInfo) {
  const config = loadStorageConfig();
  if (!config.enabled || !cloudInfo || !cloudInfo.objectKey) return null;

  if ((cloudInfo.backend || 'remote') === 'local') {
    return fs.createReadStream(getLocalObjectPath(dataDir, cloudInfo.objectKey));
  }

  const client = getS3Client();
  if (!client) throw new Error('Remote storage credentials are not configured');
  const result = await client.send(new GetObjectCommand({
    Bucket: config.bucket,
    Key: cloudInfo.objectKey,
  }));
  return result.Body;
}

function removeIndexEntry(dataDir, relPath) {
  const config = loadStorageConfig();
  if (!config.enabled) return;
  const index = loadIndex(dataDir);
  if (index.files[relPath]) {
    delete index.files[relPath];
    saveIndex(dataDir, index);
  }
}

async function cleanupOrphanedObjects(dataDir, sharedDir) {
  const config = loadStorageConfig();
  if (!config.enabled) return { removed: 0, errors: 0 };

  const index = loadIndex(dataDir);
  const files = Object.keys(index.files || {});
  let removed = 0;
  let errors = 0;

  for (const relPath of files) {
    const fullPath = path.resolve(path.join(sharedDir, relPath));
    const insideSharedDir = isPathInside(sharedDir, fullPath);
    const stillExists = insideSharedDir && fs.existsSync(fullPath) && fs.statSync(fullPath).isFile();
    if (!stillExists) {
      try {
        const ok = await deleteCloudObjectForPath(dataDir, relPath);
        if (ok) removed++;
        else errors++;
      } catch {
        errors++;
      }
    }
  }

  if (removed > 0 || errors > 0) {
    console.log(`[Storage] Cleanup complete: ${removed} removed, ${errors} errors`);
  }
  return { removed, errors };
}

async function cleanupColdObjects(dataDir) {
  const config = loadStorageConfig();
  if (!config.enabled) return { removed: 0, errors: 0 };

  const now = Date.now();
  const index = loadIndex(dataDir);
  const files = Object.keys(index.files || {});
  let removed = 0;
  let errors = 0;

  for (const relPath of files) {
    const entry = index.files[relPath];
    const lastAccessed = entry.lastAccessedAt ? Date.parse(entry.lastAccessedAt) : Date.parse(entry.uploadedAt);
    if (now - lastAccessed > config.hotDurationMs) {
      try {
        const ok = await deleteCloudObjectForPath(dataDir, relPath);
        if (ok) removed++;
        else errors++;
      } catch {
        errors++;
      }
    }
  }

  if (removed > 0 || errors > 0) {
    console.log(`[Storage] Cold cleanup complete: ${removed} removed, ${errors} errors`);
  }
  return { removed, errors };
}

function calculateWeightedScore(entry, now) {
  const ageMs = now - (entry.lastAccessedAt ? Date.parse(entry.lastAccessedAt) : Date.parse(entry.uploadedAt));
  const ageHours = ageMs / (1000 * 60 * 60);
  const sizeMB = (entry.size || 0) / (1024 * 1024);
  const ageWeight = 1.0;
  const sizeWeight = 2.0;
  return ageWeight * ageHours + sizeWeight * sizeMB;
}

async function enforceStorageLimit(dataDir) {
  const config = loadStorageConfig();
  if (!config.enabled) return { removed: 0 };

  const index = loadIndex(dataDir);
  const localResult = await enforceBackendLimit(dataDir, index, 'local', config.maxStorageBytes);
  const remoteResult = config.remoteMaxBytes > 0
    ? await enforceBackendLimit(dataDir, loadIndex(dataDir), 'remote', config.remoteMaxBytes)
    : { removed: 0, freedBytes: 0 };

  return {
    removed: localResult.removed + remoteResult.removed,
    freedBytes: (localResult.freedBytes || 0) + (remoteResult.freedBytes || 0),
  };
}

async function enforceBackendLimit(dataDir, index, backend, limitBytes) {
  let total = getStorageBytes(index, backend);
  const threshold = limitBytes * 0.8;
  if (limitBytes <= 0 || total <= threshold) return { removed: 0, freedBytes: 0 };

  const now = Date.now();
  const entries = Object.entries(index.files || {})
    .filter(([, entry]) => (entry.backend || 'remote') === backend)
    .map(([relPath, entry]) => ({
      relPath,
      entry,
      score: calculateWeightedScore(entry, now),
    }))
    .sort((a, b) => b.score - a.score);

  let removed = 0;
  let freedBytes = 0;
  for (const { relPath, entry } of entries) {
    if (total <= threshold) break;
    const ok = await deleteCloudObjectForPath(dataDir, relPath);
    if (ok) {
      total -= entry.size || 0;
      freedBytes += entry.size || 0;
      removed++;
    }
  }

  if (removed > 0) {
    console.log(`[Storage] Weighted cleanup (${backend}): ${removed} objects removed, ${formatBytes(freedBytes)} freed, target ${formatBytes(threshold)}`);
  }
  return { removed, freedBytes };
}

function startPeriodicCleanup(dataDir, sharedDir) {
  const config = loadStorageConfig();
  if (!config.enabled || cleanupTimer) return;

  cleanupTimer = setInterval(async () => {
    try {
      await cleanupColdObjects(dataDir);
      await enforceStorageLimit(dataDir);
      if (config.provider === 'qiniu') {
        await checkQuotaIfNeeded(dataDir);
      }
    } catch (err) {
      console.error('[Storage] Periodic cleanup failed:', err.message);
    }
  }, config.cleanupIntervalMs);

  console.log(`[Storage] Periodic cleanup started: every ${config.cleanupIntervalMs / 1000}s, hot duration ${config.hotDurationMs / 1000}s, max ${config.maxStorageBytes / 1024 / 1024}MB`);
}

function stopPeriodicCleanup() {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}

module.exports = {
  loadStorageConfig,
  loadIndex,
  uploadFileToCloud,
  getCloudRedirectInfo,
  createCloudReadStream,
  deleteCloudObjectForPath,
  removeIndexEntry,
  cleanupOrphanedObjects,
  cleanupColdObjects,
  enforceStorageLimit,
  startPeriodicCleanup,
  stopPeriodicCleanup,
  isStorageEnabled,
  getProvider,
  getTotalStorageBytes,
};
