const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream');
const tar = require('tar');
const packageJson = require('./package.json');

const app = express();
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = Buffer.from(buf);
  },
}));
app.use(express.static(path.join(__dirname, 'public')));

const MAX_TEXTS = 100;
const TEXT_EXPIRY_MS = 24 * 60 * 60 * 1000;
const MAX_CONCURRENT_DOWNLOADS = 3;
const REQUEST_AUTH_WINDOW_MS = 5 * 60 * 1000;
const REQUEST_NONCE_TTL_MS = 10 * 60 * 1000;
const MAX_NONCES_PER_DEVICE = 512;
const PAIR_SESSION_TTL_MS = Number.parseInt(process.env.PAIR_SESSION_TTL_MS || String(10 * 60 * 1000), 10);
const DEVICE_LAST_SEEN_PERSIST_MS = 60 * 1000;
const MAX_ARCHIVE_PATHS = 100;
let activeDownloads = 0;
const seenRequestNonces = new Map();

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const sharedDir = path.resolve(process.env.SHARED_DIR || path.join(__dirname, 'shared'));

// ============ Persistent State ============

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    }
  } catch (e) { console.error('[STATE] Failed to load:', e.message); }
  return null;
}

function saveState(data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(data, null, 2));
}

function logEvent(event, fields = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...fields,
  }));
}

function normalizeTimestamp(value, fallback = null) {
  if (typeof value !== 'string' || !value) return fallback;
  return Number.isFinite(Date.parse(value)) ? value : fallback;
}

function normalizeDevice(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = typeof raw.id === 'string' && raw.id ? raw.id : null;
  if (!id) return null;
  const pairedAt = normalizeTimestamp(raw.pairedAt, new Date().toISOString());
  return {
    id,
    name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim().slice(0, 80) : id,
    type: typeof raw.type === 'string' && raw.type.trim() ? raw.type.trim().slice(0, 40) : 'unknown',
    pairedAt,
    lastSeenAt: normalizeTimestamp(raw.lastSeenAt, null),
    revokedAt: normalizeTimestamp(raw.revokedAt, null),
  };
}

function activeDeviceCount() {
  return devices.filter((entry) => !entry.revokedAt).length;
}

function findDeviceById(deviceId) {
  return devices.find((entry) => entry.id === deviceId) || null;
}

function findActiveDeviceById(deviceId) {
  return devices.find((entry) => entry.id === deviceId && !entry.revokedAt) || null;
}

function serializeDevice(device) {
  return {
    id: device.id,
    name: device.name,
    type: device.type,
    pairedAt: device.pairedAt,
    lastSeenAt: device.lastSeenAt,
    revokedAt: device.revokedAt,
    active: !device.revokedAt,
  };
}

// Master key: generated once, persisted forever
let masterKey = null; // Buffer, 32 bytes
let devices = [];     // [{ id, name, type, pairedAt, lastSeenAt, revokedAt }]

const saved = loadState();
if (saved && saved.masterKey) {
  masterKey = Buffer.from(saved.masterKey, 'hex');
  devices = Array.isArray(saved.devices)
    ? saved.devices.map((entry) => normalizeDevice(entry)).filter(Boolean)
    : [];
  console.log(`[STATE] Loaded master key, ${activeDeviceCount()} active paired device(s)`);
} else {
  masterKey = crypto.randomBytes(32);
  devices = [];
  saveState({ masterKey: masterKey.toString('hex'), devices });
  console.log('[STATE] Generated new master key');
}

function persistDevices() {
  saveState({ masterKey: masterKey.toString('hex'), devices });
}

// Admin token: random per-run, written to file for CLI access
const ADMIN_TOKEN_FILE = path.join(DATA_DIR, '.admin-token');
const adminToken = crypto.randomBytes(16).toString('hex');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.writeFileSync(ADMIN_TOKEN_FILE, adminToken, { mode: 0o600 });

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token !== adminToken) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ============ Crypto Helpers ============

function generatePin() { return crypto.randomInt(100000, 999999).toString(); }

function generateECDHKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return { ecdh, publicKey: ecdh.getPublicKey('hex') };
}

function hkdf(ikm, salt, info, length = 32) {
  return crypto.hkdfSync('sha256', ikm, salt, info, length);
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function deriveRequestAuthKey(deviceId) {
  return Buffer.from(hkdf(masterKey, 'syncd-request-auth', `device:${deviceId}`, 32));
}

function safeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (left.length !== right.length || left.length % 2 !== 0) return false;
  try {
    const leftBuf = Buffer.from(left, 'hex');
    const rightBuf = Buffer.from(right, 'hex');
    return leftBuf.length === rightBuf.length && crypto.timingSafeEqual(leftBuf, rightBuf);
  } catch {
    return false;
  }
}

function buildRequestSignatureMessage(method, originalUrl, timestamp, nonce, bodyHash) {
  return [method.toUpperCase(), originalUrl, timestamp, nonce, bodyHash].join('\n');
}

function parseSinceCursor(value) {
  if (value === undefined || value === null || value === '') return null;
  if (/^\d+$/.test(String(value))) {
    const timestampMs = Number(value);
    return Number.isFinite(timestampMs) ? timestampMs : null;
  }

  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function pruneSeenNonces(now = Date.now()) {
  for (const [deviceId, entries] of seenRequestNonces.entries()) {
    for (const [nonce, seenAt] of entries.entries()) {
      if (now - seenAt > REQUEST_NONCE_TTL_MS) {
        entries.delete(nonce);
      }
    }
    if (entries.size === 0) {
      seenRequestNonces.delete(deviceId);
    }
  }
}

function hasSeenNonce(deviceId, nonce) {
  const entries = seenRequestNonces.get(deviceId);
  return !!entries && entries.has(nonce);
}

function rememberNonce(deviceId, nonce, now = Date.now()) {
  let entries = seenRequestNonces.get(deviceId);
  if (!entries) {
    entries = new Map();
    seenRequestNonces.set(deviceId, entries);
  }

  entries.set(nonce, now);
  if (entries.size <= MAX_NONCES_PER_DEVICE) return;

  const overflow = entries.size - MAX_NONCES_PER_DEVICE;
  let removed = 0;
  for (const key of entries.keys()) {
    entries.delete(key);
    removed++;
    if (removed >= overflow) break;
  }
}

function rememberDeviceSeen(device, now = Date.now()) {
  const seenAt = new Date(now).toISOString();
  const lastSeenMs = device.lastSeenAt ? Date.parse(device.lastSeenAt) : 0;
  device.lastSeenAt = seenAt;
  if (!Number.isFinite(lastSeenMs) || now - lastSeenMs >= DEVICE_LAST_SEEN_PERSIST_MS) {
    persistDevices();
  }
}

function requireDeviceAuth(req, res, next) {
  const deviceId = req.headers['x-device-id'];
  const timestamp = req.headers['x-auth-timestamp'];
  const nonce = req.headers['x-auth-nonce'];
  const signature = req.headers['x-auth-signature'];
  if (!deviceId || !timestamp || !nonce || !signature) {
    if (activeDeviceCount() === 0) {
      return res.status(403).json({ error: 'Not paired' });
    }
    return res.status(401).json({ error: 'Missing request authentication headers' });
  }

  const device = findActiveDeviceById(deviceId);
  if (!device) {
    return res.status(401).json({ error: 'Unknown device' });
  }

  const timestampMs = Number(timestamp);
  if (!Number.isFinite(timestampMs)) {
    return res.status(401).json({ error: 'Invalid request timestamp' });
  }

  const now = Date.now();
  if (Math.abs(now - timestampMs) > REQUEST_AUTH_WINDOW_MS) {
    return res.status(401).json({ error: 'Request timestamp expired' });
  }

  pruneSeenNonces(now);
  if (hasSeenNonce(deviceId, nonce)) {
    return res.status(409).json({ error: 'Replay detected' });
  }

  const bodyHash = sha256Hex(req.rawBody || Buffer.alloc(0));
  const expectedSignature = hmac(
    deriveRequestAuthKey(deviceId),
    buildRequestSignatureMessage(req.method, req.originalUrl, String(timestamp), String(nonce), bodyHash)
  );
  if (!safeEqualHex(expectedSignature, signature)) {
    return res.status(401).json({ error: 'Invalid request signature' });
  }

  rememberNonce(deviceId, nonce, now);
  rememberDeviceSeen(device, now);
  req.authenticatedDeviceId = deviceId;
  req.authenticatedDevice = device;
  next();
}

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), ciphertext: encrypted.toString('hex'), tag: tag.toString('hex') };
}

function createEncryptStream(key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return { cipher, iv };
}

function streamEncryptedResponse({ res, sourceStream, extraHeaders = {}, label, onComplete }) {
  const { cipher, iv } = createEncryptStream(masterKey);
  let completed = false;

  const finish = (err) => {
    if (completed) return;
    completed = true;
    if (onComplete) onComplete(err);
  };

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Encrypted-IV', iv.toString('hex'));
  res.setHeader('X-Encrypted-Tag-Length', '16');

  for (const [header, value] of Object.entries(extraHeaders)) {
    res.setHeader(header, value);
  }

  cipher.pipe(res, { end: false });

  res.on('close', () => {
    if (res.writableEnded) return;
    const err = new Error('Client disconnected');
    sourceStream.destroy(err);
    cipher.destroy(err);
    finish(err);
  });

  pipeline(sourceStream, cipher, (err) => {
    if (completed) return;
    if (err) {
      console.error(`[${label}] Stream error:`, err.message);
      finish(err);
      if (!res.headersSent) {
        res.status(500).json({ error: `${label} failed` });
      } else if (!res.destroyed) {
        res.destroy(err);
      }
      return;
    }

    try {
      const tag = cipher.getAuthTag();
      res.end(tag, () => finish());
    } catch (tagErr) {
      console.error(`[${label}] Finalize error:`, tagErr.message);
      finish(tagErr);
      if (!res.destroyed) res.destroy(tagErr);
    }
  });
}

// ============ Pending Pairing Session ============
// Ephemeral — only lives in memory, one at a time

let pendingPair = null; // { pin, keyPair, attempts, maxAttempts, createdAt, expiresAt }

function clearPairSession(reason) {
  if (!pendingPair) return;
  if (reason) {
    logEvent('pair_cleared', {
      reason,
      expiresAt: pendingPair.expiresAt,
    });
  }
  pendingPair = null;
}

function getPendingPair() {
  if (!pendingPair) return null;
  if (Date.now() >= Date.parse(pendingPair.expiresAt)) {
    clearPairSession('expired');
    return null;
  }
  return pendingPair;
}

function serializePairSession(session = getPendingPair()) {
  if (!session) {
    return {
      active: false,
      expiresAt: null,
      attemptsRemaining: 0,
    };
  }

  return {
    active: true,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    attemptsRemaining: Math.max(session.maxAttempts - session.attempts, 0),
  };
}

function createPairSession() {
  pendingPair = {
    pin: generatePin(),
    keyPair: generateECDHKeyPair(),
    attempts: 0,
    maxAttempts: 5,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + PAIR_SESSION_TTL_MS).toISOString(),
  };
  console.log('\n========================================');
  console.log(`  Pairing PIN: ${pendingPair.pin}`);
  console.log('  Enter this PIN on the remote device');
  console.log('========================================\n');
  logEvent('pair_created', {
    expiresAt: pendingPair.expiresAt,
  });
  return pendingPair.pin;
}

// ============ API: Pairing ============

app.get('/api/status', (req, res) => {
  const session = getPendingPair();
  res.json({
    paired: activeDeviceCount() > 0,
    pairedDeviceCount: activeDeviceCount(),
    pendingPair: !!session,
    pendingPairExpiresAt: session ? session.expiresAt : null,
  });
});

app.get('/api/pair/status', (req, res) => {
  res.json({
    ...serializePairSession(),
    pairedDeviceCount: activeDeviceCount(),
  });
});

app.get('/api/session', requireDeviceAuth, (req, res) => {
  res.json({
    ok: true,
    deviceId: req.authenticatedDeviceId,
    device: serializeDevice(req.authenticatedDevice),
  });
});

app.get('/healthz', (req, res) => {
  const session = getPendingPair();
  res.json({
    ok: true,
    service: packageJson.name,
    version: packageJson.version,
    paired: activeDeviceCount() > 0,
    pairedDeviceCount: activeDeviceCount(),
    pendingPair: !!session,
    pendingPairExpiresAt: session ? session.expiresAt : null,
    uptimeSeconds: Math.floor(process.uptime()),
  });
});

app.get('/api/pair/init', (req, res) => {
  const session = getPendingPair();
  if (!session) {
    return res.status(400).json({ error: 'No active pairing session. Generate a new PIN on the server.' });
  }
  res.json({
    serverPublicKey: session.keyPair.publicKey,
    ...serializePairSession(session),
  });
});

app.post('/api/pair/verify', (req, res) => {
  const session = getPendingPair();
  if (!session) {
    return res.status(400).json({ error: 'No active pairing session' });
  }
  if (session.attempts >= session.maxAttempts) {
    clearPairSession('attempt_limit_reached');
    return res.status(403).json({ error: 'Too many attempts. Generate a new PIN.' });
  }

  const { clientPublicKey, proof, deviceId, deviceName, deviceType } = req.body;
  if (!clientPublicKey || !proof || !deviceId) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  if (typeof deviceId !== 'string' || !deviceId.trim()) {
    return res.status(400).json({ error: 'Invalid deviceId' });
  }

  session.attempts++;

  try {
    const sharedSecret = session.keyPair.ecdh.computeSecret(Buffer.from(clientPublicKey, 'hex'));
    const authKey = Buffer.from(hkdf(sharedSecret, 'syncd-auth', 'pin-verify', 32));

    if (proof !== hmac(authKey, session.pin)) {
      const remaining = session.maxAttempts - session.attempts;
      console.log(`[PAIR] Invalid PIN attempt (${remaining} remaining)`);
      logEvent('pair_failed', {
        reason: 'invalid_pin',
        deviceId: deviceId.trim(),
        remaining,
      });
      return res.status(401).json({ error: 'Invalid PIN', remaining, expiresAt: session.expiresAt });
    }

    // PIN verified — encrypt master key with transport key and send to client
    const transportKey = Buffer.from(hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32));
    const encryptedMasterKey = encrypt(transportKey, masterKey);
    const serverProof = hmac(authKey, 'server-confirmed');

    const id = deviceId.trim().slice(0, 120);
    const pairedAt = new Date().toISOString();
    const existingDevice = findDeviceById(id);
    const normalizedName = typeof deviceName === 'string' && deviceName.trim()
      ? deviceName.trim().slice(0, 80)
      : (existingDevice ? existingDevice.name : id);
    const normalizedType = typeof deviceType === 'string' && deviceType.trim()
      ? deviceType.trim().slice(0, 40)
      : (existingDevice ? existingDevice.type : 'unknown');
    if (existingDevice) {
      existingDevice.name = normalizedName;
      existingDevice.type = normalizedType;
      existingDevice.pairedAt = pairedAt;
      existingDevice.lastSeenAt = pairedAt;
      existingDevice.revokedAt = null;
    } else {
      devices.push({
        id,
        name: normalizedName,
        type: normalizedType,
        pairedAt,
        lastSeenAt: pairedAt,
        revokedAt: null,
      });
    }
    persistDevices();
    clearPairSession('paired');

    console.log(`[PAIR] Device paired: ${id} (${activeDeviceCount()} total)`);
    logEvent('pair_succeeded', {
      deviceId: id,
      deviceName: normalizedName,
      deviceType: normalizedType,
      deviceCount: activeDeviceCount(),
    });

    res.json({ success: true, serverProof, encryptedMasterKey });
  } catch (err) {
    console.error('[PAIR] Error:', err.message);
    logEvent('pair_failed', {
      reason: 'key_exchange_failed',
      error: err.message,
    });
    res.status(500).json({ error: 'Key exchange failed' });
  }
});

// ============ Local-only: Generate new PIN ============

app.post('/api/local/new-pin', requireAdmin, (req, res) => {
  const pin = createPairSession();
  res.json({ pin, ...serializePairSession(pendingPair) });
});

app.get('/api/local/devices', requireAdmin, (req, res) => {
  res.json({
    devices: devices
      .slice()
      .sort((left, right) => Date.parse(right.pairedAt || 0) - Date.parse(left.pairedAt || 0))
      .map((entry) => serializeDevice(entry)),
  });
});

app.delete('/api/local/devices/:id', requireAdmin, (req, res) => {
  const device = findActiveDeviceById(req.params.id);
  if (!device) {
    return res.status(404).json({ error: 'Device not found' });
  }
  device.revokedAt = new Date().toISOString();
  persistDevices();
  seenRequestNonces.delete(device.id);
  logEvent('device_revoked', {
    deviceId: device.id,
    deviceName: device.name,
  });
  res.json({ success: true, device: serializeDevice(device) });
});

// ============ File Sharing (encrypted) ============

function walkDir(dir, prefix = '') {
  if (!fs.existsSync(dir)) return [];
  let results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push({ name: relPath, type: 'dir' });
      results = results.concat(walkDir(fullPath, relPath));
    } else if (entry.isFile()) {
      const stat = fs.statSync(fullPath);
      results.push({ name: relPath, type: 'file', size: stat.size, modified: stat.mtime.toISOString() });
    }
  }
  return results;
}

function resolveSharedEntry(relPath) {
  const normalized = String(relPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .replace(/\/{2,}/g, '/');
  const fullPath = path.resolve(path.join(sharedDir, normalized));
  if (!fullPath.startsWith(path.resolve(sharedDir))) return null;
  return { relPath: normalized, fullPath };
}

function getEntrySize(fullPath) {
  const stat = fs.statSync(fullPath);
  if (stat.isFile()) return stat.size;
  if (!stat.isDirectory()) return 0;

  let total = 0;
  for (const entry of fs.readdirSync(fullPath, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    total += getEntrySize(path.join(fullPath, entry.name));
  }
  return total;
}

function prepareArchivePaths(paths) {
  if (!Array.isArray(paths) || paths.length === 0) {
    return { error: 'Missing paths' };
  }
  if (paths.length > MAX_ARCHIVE_PATHS) {
    return { error: `Too many archive paths (max ${MAX_ARCHIVE_PATHS})` };
  }

  const uniquePaths = [];
  const seen = new Set();
  let totalSize = 0;

  for (const rawPath of paths) {
    if (typeof rawPath !== 'string' || !rawPath.trim()) {
      return { error: 'Archive path must be a non-empty string' };
    }
    const resolved = resolveSharedEntry(rawPath.trim());
    if (!resolved || !resolved.relPath) {
      return { error: 'Access denied' };
    }
    if (seen.has(resolved.relPath)) continue;
    if (!fs.existsSync(resolved.fullPath)) {
      return { error: `Path not found: ${resolved.relPath}` };
    }
    const stat = fs.statSync(resolved.fullPath);
    if (!stat.isFile() && !stat.isDirectory()) {
      return { error: `Unsupported path: ${resolved.relPath}` };
    }
    seen.add(resolved.relPath);
    uniquePaths.push(resolved.relPath);
    totalSize += getEntrySize(resolved.fullPath);
  }

  if (uniquePaths.length === 0) {
    return { error: 'No valid paths selected' };
  }

  return {
    paths: uniquePaths,
    totalSize,
  };
}

app.get('/api/files', requireDeviceAuth, (req, res) => {
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });
  const tree = walkDir(sharedDir);
  res.json({ encrypted: encrypt(masterKey, Buffer.from(JSON.stringify(tree))) });
});

app.get(/^\/api\/files\/(.*)/, requireDeviceAuth, (req, res) => {
  const resolved = resolveSharedEntry(req.params[0] || '');
  if (!resolved || !resolved.relPath) return res.status(403).json({ error: 'Access denied' });
  if (!fs.existsSync(resolved.fullPath) || !fs.statSync(resolved.fullPath).isFile()) return res.status(404).json({ error: 'Not found' });
  
  const stat = fs.statSync(resolved.fullPath);
  const fileSize = stat.size;
  
  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  streamEncryptedResponse({
    res,
    sourceStream: fs.createReadStream(resolved.fullPath),
    label: 'FILE',
    extraHeaders: {
      'X-File-Name': encodeURIComponent(path.basename(resolved.relPath)),
      'X-File-Size': String(fileSize),
    },
    onComplete: (err) => {
      activeDownloads--;
      if (!err) {
        logEvent('file_downloaded', {
          deviceId: req.authenticatedDeviceId,
          path: resolved.relPath,
          size: fileSize,
        });
      }
    },
  });
});

// ============ Batch Download ============

app.post('/api/archive', requireDeviceAuth, (req, res) => {
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });

  const archive = prepareArchivePaths(req.body?.paths);
  if (archive.error) {
    return res.status(400).json({ error: archive.error });
  }
  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  streamEncryptedResponse({
    res,
    sourceStream: tar.create({ gzip: true, cwd: sharedDir }, archive.paths),
    label: 'ARCHIVE',
    extraHeaders: {
      'X-File-Name': encodeURIComponent('selected.tar.gz'),
      'X-Archive-Count': String(archive.paths.length),
      'X-Archive-Total-Size': String(archive.totalSize),
    },
    onComplete: (err) => {
      activeDownloads--;
      if (!err) {
        logEvent('archive_downloaded', {
          deviceId: req.authenticatedDeviceId,
          pathCount: archive.paths.length,
          totalSize: archive.totalSize,
        });
      }
    },
  });
});

app.get('/api/batch', requireDeviceAuth, (req, res) => {
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });

  const sinceMs = parseSinceCursor(req.query.since);
  const snapshotStartedAt = Date.now();

  const files = [];
  let totalSize = 0;
  for (const entry of walkDir(sharedDir)) {
    if (entry.type !== 'file') continue;
    const modifiedMs = Date.parse(entry.modified);
    if (sinceMs !== null && Number.isFinite(modifiedMs) && modifiedMs <= sinceMs) continue;
    files.push(entry.name);
    totalSize += entry.size;
  }

  if (files.length === 0) {
    return res.status(204).end();
  }

  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  streamEncryptedResponse({
    res,
    sourceStream: tar.create({ gzip: true, cwd: sharedDir }, files),
    label: 'BATCH',
    extraHeaders: {
      'X-Batch-Count': String(files.length),
      'X-Batch-Total-Size': String(totalSize),
      'X-Batch-Snapshot-At': String(snapshotStartedAt),
    },
    onComplete: (err) => {
      activeDownloads--;
      if (!err) {
        logEvent('batch_synced', {
          deviceId: req.authenticatedDeviceId,
          fileCount: files.length,
          totalSize,
          snapshotStartedAt,
        });
      }
    },
  });
});

// ============ Text Sharing ============

let sharedTexts = [];

function cleanExpiredTexts() {
  const now = Date.now();
  const before = sharedTexts.length;
  sharedTexts = sharedTexts.filter(t => now - new Date(t.timestamp).getTime() < TEXT_EXPIRY_MS);
  if (sharedTexts.length < before) {
    console.log(`[TEXT] Cleaned ${before - sharedTexts.length} expired texts`);
    logEvent('text_cleaned', {
      removed: before - sharedTexts.length,
    });
  }
}

app.post('/api/text', requireDeviceAuth, (req, res) => {
  const { encryptedText } = req.body;
  if (!encryptedText) return res.status(400).json({ error: 'Missing encryptedText' });
  
  cleanExpiredTexts();
  
  if (sharedTexts.length >= MAX_TEXTS) {
    sharedTexts.shift();
  }
  
  sharedTexts.push({
    id: crypto.randomUUID(),
    data: encryptedText,
    timestamp: new Date().toISOString(),
    deviceId: req.authenticatedDeviceId,
  });
  console.log(`[TEXT] New encrypted text (${sharedTexts.length} total)`);
  logEvent('text_shared', {
    deviceId: req.authenticatedDeviceId,
    totalTexts: sharedTexts.length,
  });
  res.json({ success: true });
});

app.get('/api/texts', requireDeviceAuth, (req, res) => {
  cleanExpiredTexts();
  res.json({ texts: sharedTexts });
});

// ============ Start Server ============

const PORT = process.env.PORT || 21891;
app.listen(PORT, () => {
  console.log(`cloudsysncd server running on http://localhost:${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
  console.log(`Shared directory: ${sharedDir}`);
  console.log(`Paired devices: ${activeDeviceCount()}`);
  if (activeDeviceCount() === 0) {
    createPairSession();
  } else {
    console.log('\nReady. Run `node pin.js` to generate a PIN for a new device.\n');
  }
});
