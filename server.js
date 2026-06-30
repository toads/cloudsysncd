require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream');
const tar = require('tar');
const packageJson = require('./package.json');
const storage = require('./lib/cloud-storage');
const chunkedAead = require('./lib/chunked-aead');

const app = express();
app.disable('x-powered-by');

function cspSourceList(value) {
  return String(value || '')
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeBaseUrl(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function normalizeBaseUrlList(value) {
  return String(value || '')
    .split(/[\s,]+/)
    .map((entry) => normalizeBaseUrl(entry))
    .filter(Boolean);
}

function cspOriginSource(value) {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
}

const CLIENT_PRIMARY_RELAY_URL = normalizeBaseUrl(process.env.CLIENT_PRIMARY_RELAY_URL || process.env.PRIMARY_RELAY_URL);
const CLIENT_RELAY_BASE_URLS = Array.from(new Set([
  CLIENT_PRIMARY_RELAY_URL,
  ...normalizeBaseUrlList(process.env.CLIENT_RELAY_BASE_URLS || process.env.RELAY_BASE_URLS),
].filter(Boolean)));
const CLIENT_RELAY_ACCESS_KEY = process.env.CLIENT_RELAY_ACCESS_KEY || process.env.SYNCD_RELAY_ACCESS_KEY || '';
const CLIENT_CF_INLINE_MAX_BYTES = Math.max(
  0,
  Number.parseInt(process.env.CLIENT_CF_INLINE_MAX_BYTES || String(200 * 1024), 10) || 0
);
const CLIENT_ALLOW_INSECURE_RELAY_FALLBACK = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.CLIENT_ALLOW_INSECURE_RELAY_FALLBACK || '').trim().toLowerCase()
);
const CSP_CONNECT_SRC = Array.from(new Set([
  "'self'",
  ...CLIENT_RELAY_BASE_URLS.map((entry) => cspOriginSource(entry)),
  ...cspSourceList(process.env.CSP_CONNECT_SRC),
].filter(Boolean)));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self'",
      "img-src 'self' data: blob:",
      `connect-src ${CSP_CONNECT_SRC.join(' ')}`,
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join('; ')
  );
  next();
});
app.use(express.json({
  limit: process.env.JSON_BODY_LIMIT || '2mb',
  verify: (req, res, buf) => {
    req.rawBody = Buffer.from(buf);
  },
}));
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'ignore',
  index: 'index.html',
}));

const MAX_TEXTS = 100;
const TEXT_EXPIRY_MS = 24 * 60 * 60 * 1000;
const MAX_CONCURRENT_DOWNLOADS = 3;
const REQUEST_AUTH_WINDOW_MS = 5 * 60 * 1000;
const REQUEST_NONCE_TTL_MS = 10 * 60 * 1000;
const MAX_NONCES_PER_DEVICE = 512;
const PAIR_SESSION_TTL_MS = Number.parseInt(process.env.PAIR_SESSION_TTL_MS || String(10 * 60 * 1000), 10);
const DEVICE_LAST_SEEN_PERSIST_MS = 60 * 1000;
const MAX_ARCHIVE_PATHS = 100;
const CHUNKED_THRESHOLD_BYTES = Math.max(
  1024 * 1024,
  Number.parseInt(process.env.CHUNKED_THRESHOLD_BYTES || String(64 * 1024 * 1024), 10) || 64 * 1024 * 1024
);
let activeDownloads = 0;
const seenRequestNonces = new Map();

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const sharedDir = path.resolve(process.env.SHARED_DIR || path.join(__dirname, 'shared'));
const repoSharedSourceDir = path.resolve(path.join(__dirname, 'shared'));
const HIDDEN_SHARED_RELATIVE_PATHS = new Set(
  sharedDir === repoSharedSourceDir ? ['sync_download.py', '__pycache__'] : []
);
const PROTECTED_SHARED_RELATIVE_PATHS = new Set(
  sharedDir === repoSharedSourceDir ? ['sync_download.py'] : []
);

// ============ Persistent State ============

function ensurePrivateDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(DATA_DIR, 0o700); } catch {}
}

function writePrivateJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch {}
}

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    }
  } catch (e) { console.error('[STATE] Failed to load:', e.message); }
  return null;
}

function saveState(data) {
  ensurePrivateDataDir();
  writePrivateJson(STATE_FILE, data);
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

function normalizeSharedRelPath(relPath) {
  return String(relPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '');
}

function isPathInside(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === '' || (!!relative && !relative.startsWith('..') && !path.isAbsolute(relative));
}

function getRealPathIfExists(candidate) {
  try {
    if (!fs.existsSync(candidate)) return null;
    return fs.realpathSync(candidate);
  } catch {
    return null;
  }
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
ensurePrivateDataDir();
fs.writeFileSync(ADMIN_TOKEN_FILE, adminToken, { mode: 0o600 });
try { fs.chmodSync(ADMIN_TOKEN_FILE, 0o600); } catch {}

function isLoopbackAddress(address) {
  const normalized = String(address || '')
    .replace(/^::ffff:/, '')
    .toLowerCase();
  return normalized === '::1' || normalized === 'localhost' || normalized.startsWith('127.');
}

function isLoopbackRequest(req) {
  return isLoopbackAddress(req.socket?.remoteAddress || req.ip);
}

function requireAdmin(req, res, next) {
  if (!isLoopbackRequest(req)) {
    return res.status(403).json({ error: 'Local admin API only accepts loopback requests' });
  }
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

function streamChunkedEncryptedResponse({ res, sourceStream, extraHeaders = {}, label, onComplete }) {
  let completed = false;

  const finish = (err) => {
    if (completed) return;
    completed = true;
    if (onComplete) onComplete(err);
  };

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Encryption-Format', 'chunked-aead-v1');

  for (const [header, value] of Object.entries(extraHeaders)) {
    res.setHeader(header, value);
  }

  const { stream } = chunkedAead.createChunkedAeadStream(sourceStream, masterKey);

  res.on('close', () => {
    if (res.writableEnded) return;
    const err = new Error('Client disconnected');
    sourceStream.destroy(err);
    stream.destroy(err);
    finish(err);
  });

  pipeline(stream, res, (err) => {
    if (completed) return;
    if (err) {
      console.error(`[${label}] Chunked stream error:`, err.message);
      finish(err);
      if (!res.headersSent) {
        res.status(500).json({ error: `${label} failed` });
      } else if (!res.destroyed) {
        res.destroy(err);
      }
      return;
    }
    finish();
  });
}

function streamCachedEncryptedResponse({ res, sourceStream, extraHeaders = {}, label, onComplete }) {
  let completed = false;

  const finish = (err) => {
    if (completed) return;
    completed = true;
    if (onComplete) onComplete(err);
  };

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Encryption-Format', 'chunked-aead-v1');

  for (const [header, value] of Object.entries(extraHeaders)) {
    res.setHeader(header, value);
  }

  res.on('close', () => {
    if (res.writableEnded) return;
    const err = new Error('Client disconnected');
    sourceStream.destroy(err);
    finish(err);
  });

  pipeline(sourceStream, res, (err) => {
    if (completed) return;
    if (err) {
      console.error(`[${label}] Cached stream error:`, err.message);
      finish(err);
      if (!res.headersSent) {
        res.status(500).json({ error: `${label} failed` });
      } else if (!res.destroyed) {
        res.destroy(err);
      }
      return;
    }
    finish();
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

app.get('/api/transport-config', requireDeviceAuth, (req, res) => {
  const relayPayload = CLIENT_RELAY_ACCESS_KEY
    ? encrypt(masterKey, Buffer.from(JSON.stringify({
      version: 1,
      relayAccessKey: CLIENT_RELAY_ACCESS_KEY,
      authScheme: 'hmac-v1',
      issuedAt: new Date().toISOString(),
    })))
    : null;

  res.json({
    primaryRelayBaseUrl: CLIENT_PRIMARY_RELAY_URL,
    relayBaseUrls: CLIENT_RELAY_BASE_URLS,
    cfInlineMaxBytes: CLIENT_CF_INLINE_MAX_BYTES,
    allowInsecureRelayFallback: CLIENT_ALLOW_INSECURE_RELAY_FALLBACK,
    relayAccessKeyAvailable: Boolean(CLIENT_RELAY_ACCESS_KEY),
    relayAccessAuthScheme: CLIENT_RELAY_ACCESS_KEY ? 'hmac-v1' : '',
    encryptedRelayAccessKey: relayPayload,
    objectFallbackEnabled: storage.isStorageEnabled(),
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

app.get('/api/client-config', (req, res) => {
  res.json({
    primaryRelayBaseUrl: CLIENT_PRIMARY_RELAY_URL,
    relayBaseUrls: CLIENT_RELAY_BASE_URLS,
    cfInlineMaxBytes: CLIENT_CF_INLINE_MAX_BYTES,
    allowInsecureRelayFallback: CLIENT_ALLOW_INSECURE_RELAY_FALLBACK,
    relayAccessKeyRequired: Boolean(CLIENT_PRIMARY_RELAY_URL && CLIENT_RELAY_ACCESS_KEY),
    objectFallbackEnabled: storage.isStorageEnabled(),
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
    if (isInternalSharedRelPath(relPath)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    const stat = fs.statSync(fullPath);
    if (entry.isDirectory()) {
      results.push({ name: relPath, type: 'dir', modified: stat.mtime.toISOString() });
      results = results.concat(walkDir(fullPath, relPath));
    } else if (entry.isFile()) {
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
  if (isInternalSharedRelPath(normalized)) return null;
  const fullPath = path.resolve(path.join(sharedDir, normalized));
  if (!isPathInside(sharedDir, fullPath)) return null;

  const realSharedDir = getRealPathIfExists(sharedDir) || path.resolve(sharedDir);
  const realFullPath = getRealPathIfExists(fullPath);
  if (realFullPath && !isPathInside(realSharedDir, realFullPath)) return null;

  return { relPath: normalized, fullPath: realFullPath || fullPath };
}

function getEntrySize(fullPath) {
  const stat = fs.statSync(fullPath);
  if (stat.isFile()) return stat.size;
  if (!stat.isDirectory()) return 0;

  let total = 0;
  for (const entry of fs.readdirSync(fullPath, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    if (entry.isSymbolicLink()) continue;
    total += getEntrySize(path.join(fullPath, entry.name));
  }
  return total;
}

function containsSymlink(fullPath) {
  if (!fs.existsSync(fullPath)) return false;
  const stat = fs.lstatSync(fullPath);
  if (stat.isSymbolicLink()) return true;
  if (!stat.isDirectory()) return false;

  for (const entry of fs.readdirSync(fullPath, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    if (entry.isSymbolicLink()) return true;
    if (entry.isDirectory() && containsSymlink(path.join(fullPath, entry.name))) return true;
  }
  return false;
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
    if (containsSymlink(resolved.fullPath)) {
      return { error: `Path contains symbolic links: ${resolved.relPath}` };
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

app.get(/^\/api\/files\/(.*)/, requireDeviceAuth, async (req, res) => {
  const resolved = resolveSharedEntry(req.params[0] || '');
  if (!resolved || !resolved.relPath) return res.status(403).json({ error: 'Access denied' });
  if (!fs.existsSync(resolved.fullPath) || !fs.statSync(resolved.fullPath).isFile()) return res.status(404).json({ error: 'Not found' });

  const stat = fs.statSync(resolved.fullPath);
  const fileSize = stat.size;

  try {
    const cloudInfo = await storage.getCloudRedirectInfo(DATA_DIR, resolved.relPath, resolved.fullPath);
    if (cloudInfo) {
      if (cloudInfo.proxy) {
        if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
          return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
        }

        activeDownloads++;
        const sourceStream = await storage.createCloudReadStream(DATA_DIR, cloudInfo);
        streamCachedEncryptedResponse({
          res,
          sourceStream,
          label: 'CACHE',
          extraHeaders: {
            'X-File-Name': encodeURIComponent(path.basename(resolved.relPath)),
            'X-File-Size': String(fileSize),
            'X-Storage-Backend': cloudInfo.backend || 'remote',
          },
          onComplete: (err) => {
            activeDownloads--;
            if (!err) {
              logEvent('file_cache_downloaded', {
                deviceId: req.authenticatedDeviceId,
                path: resolved.relPath,
                size: fileSize,
                backend: cloudInfo.backend || 'remote',
              });
            }
          },
        });
        return;
      }

      logEvent('file_cloud_redirect', {
        deviceId: req.authenticatedDeviceId,
        path: resolved.relPath,
        size: fileSize,
      });
      return res.json({
        cloud: cloudInfo,
        filename: path.basename(resolved.relPath),
        format: 'chunked-aead-v1',
      });
    }
  } catch (err) {
    console.error(`[Storage] Redirect check failed for ${resolved.relPath}:`, err.message);
  }

  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  const useChunked = fileSize > CHUNKED_THRESHOLD_BYTES;
  const streamFn = useChunked ? streamChunkedEncryptedResponse : streamEncryptedResponse;
  streamFn({
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
        logEvent(useChunked ? 'file_chunked_downloaded' : 'file_downloaded', {
          deviceId: req.authenticatedDeviceId,
          path: resolved.relPath,
          size: fileSize,
        });
      }
    },
  });
});

// ============ Batch Download ============

app.post('/api/archive', requireDeviceAuth, async (req, res) => {
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });

  const archive = prepareArchivePaths(req.body?.paths);
  if (archive.error) {
    return res.status(400).json({ error: archive.error });
  }

  if (storage.isStorageEnabled() && archive.paths.length === 1) {
    const single = archive.paths[0];
    const resolved = resolveSharedEntry(single);
    if (resolved && fs.existsSync(resolved.fullPath) && fs.statSync(resolved.fullPath).isFile()) {
      try {
        const cloudInfo = await storage.getCloudRedirectInfo(DATA_DIR, resolved.relPath, resolved.fullPath);
        if (cloudInfo) {
          if (cloudInfo.proxy) {
            if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
              return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
            }

            activeDownloads++;
            const sourceStream = await storage.createCloudReadStream(DATA_DIR, cloudInfo);
            streamCachedEncryptedResponse({
              res,
              sourceStream,
              label: 'ARCHIVE-CACHE',
              extraHeaders: {
                'X-File-Name': encodeURIComponent(path.basename(resolved.relPath)),
                'X-File-Size': String(cloudInfo.size || fs.statSync(resolved.fullPath).size),
                'X-Storage-Backend': cloudInfo.backend || 'remote',
              },
              onComplete: (err) => {
                activeDownloads--;
                if (!err) {
                  logEvent('archive_cache_downloaded', {
                    deviceId: req.authenticatedDeviceId,
                    path: resolved.relPath,
                    size: cloudInfo.size,
                    backend: cloudInfo.backend || 'remote',
                  });
                }
              },
            });
            return;
          }

          logEvent('archive_cloud_redirect', {
            deviceId: req.authenticatedDeviceId,
            path: resolved.relPath,
            size: cloudInfo.size,
          });
          return res.json({
            cloud: cloudInfo,
            filename: path.basename(resolved.relPath),
          });
        }
      } catch (err) {
        console.error(`[Storage] Archive redirect check failed for ${resolved.relPath}:`, err.message);
      }
    }
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

app.get('/api/cloud/status', requireDeviceAuth, async (req, res) => {
  try {
    const config = storage.loadStorageConfig();
    if (!config.enabled) {
      return res.json({ enabled: false });
    }

    const now = new Date();
    const nextReset = new Date(now.getFullYear(), now.getMonth() + 1, 1);

    if (config.provider === 'qiniu') {
      try {
        const qiniu = require('qiniu');
        const https = require('https');
        const mac = new qiniu.auth.digest.Mac(config.accessKeyId, config.secretAccessKey);
        const { S3Client, ListObjectsV2Command } = require('@aws-sdk/client-s3');
        const s3Client = new S3Client({
          endpoint: config.endpoint,
          region: config.region,
          credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey },
          forcePathStyle: true,
        });

        let totalSize = 0;
        let objectCount = 0;
        let continuationToken = null;

        do {
          const result = await s3Client.send(new ListObjectsV2Command({
            Bucket: config.bucket,
            MaxKeys: 1000,
            ContinuationToken: continuationToken || undefined,
          }));

          for (const obj of result.Contents || []) {
            totalSize += obj.Size || 0;
            objectCount++;
          }

          continuationToken = result.IsTruncated ? result.NextContinuationToken : null;
        } while (continuationToken);

        const maxBytes = Math.max(0, Number.parseInt(process.env.QINIU_MAX_BYTES || '10737418240', 10) || 10737418240);

        let trafficUsed = 0;
        let getRequests = 0;
        try {
          const today = new Date();
          const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
          const monthEnd = new Date(today.getFullYear(), today.getMonth() + 1, 1);
          const begin = monthStart.toISOString().replace(/[-:T]/g, '').slice(0, 14);
          const end = monthEnd.toISOString().replace(/[-:T]/g, '').slice(0, 14);

          const flowRes = await new Promise((resolve, reject) => {
            const path = `/v6/blob_io?begin=${begin}&end=${end}&g=day&select=flow&\$metric=flow_out`;
            const token = qiniu.util.generateAccessToken(mac, `https://api.qiniuapi.com${path}`);
            const options = {
              hostname: 'api.qiniuapi.com',
              path,
              method: 'GET',
              headers: { Authorization: token },
            };
            const req = https.request(options, (res) => {
              let data = '';
              res.on('data', (chunk) => data += chunk);
              res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch { resolve(data); }
              });
            });
            req.on('error', reject);
            req.end();
          });

          if (Array.isArray(flowRes)) {
            for (const day of flowRes) {
              trafficUsed += day.values?.flow || 0;
            }
          }

          const hitsRes = await new Promise((resolve, reject) => {
            const path = `/v6/blob_io?begin=${begin}&end=${end}&g=day&select=hits&\$metric=hits`;
            const token = qiniu.util.generateAccessToken(mac, `https://api.qiniuapi.com${path}`);
            const options = {
              hostname: 'api.qiniuapi.com',
              path,
              method: 'GET',
              headers: { Authorization: token },
            };
            const req = https.request(options, (res) => {
              let data = '';
              res.on('data', (chunk) => data += chunk);
              res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch { resolve(data); }
              });
            });
            req.on('error', reject);
            req.end();
          });

          if (Array.isArray(hitsRes)) {
            for (const day of hitsRes) {
              getRequests += day.values?.hits || 0;
            }
          }
        } catch (trafficErr) {
          console.error('[Cloud Status] Traffic check failed:', trafficErr.message);
        }

        let cdnTrafficUsed = 0;
        try {
          const cdnStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
          const cdnEnd = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
          const cdnDomain = String(config.cdnBucket || process.env.QINIU_CDN_DOMAIN || '').trim();
          if (!cdnDomain) throw new Error('Qiniu CDN domain is not configured');
          const cdnBody = JSON.stringify({ startDate: cdnStart, endDate: cdnEnd, granularity: 'day', domains: cdnDomain });
          const cdnPath = '/v2/tune/flux';
          const cdnUrl = `https://fusion.qiniuapi.com${cdnPath}`;
          const cdnToken = qiniu.util.generateAccessToken(mac, cdnUrl);

          const cdnRes = await new Promise((resolve, reject) => {
            const bodyBuf = Buffer.from(cdnBody);
            const opts = {
              hostname: 'fusion.qiniuapi.com', path: cdnPath, method: 'POST',
              headers: { 'Content-Type': 'application/json', Authorization: cdnToken, 'Content-Length': String(bodyBuf.length) },
            };
            const req = https.request(opts, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({}); } }); });
            req.on('error', reject);
            req.write(bodyBuf);
            req.end();
          });

          if (cdnRes.code === 200 && cdnRes.data) {
            const domain = cdnRes.data[cdnDomain];
            if (domain && domain.china) {
              for (const val of domain.china) { cdnTrafficUsed += val || 0; }
            }
          }
        } catch (cdnErr) {
          console.error('[Cloud Status] CDN traffic check failed:', cdnErr.message);
        }

        return res.json({
          enabled: true,
          provider: config.provider,
          bucket: config.bucket,
          storageUsed: totalSize,
          storageLimit: maxBytes,
          objectCount,
          usagePercent: maxBytes > 0 ? ((totalSize / maxBytes) * 100).toFixed(2) : 0,
          trafficUsed,
          trafficLimit: 10737418240,
          cdnTrafficUsed,
          cdnTrafficLimit: 10737418240,
          getRequests,
          getRequestsLimit: 1000000,
          nextResetAt: nextReset.toISOString(),
          daysUntilReset: Math.ceil((nextReset - now) / (1000 * 60 * 60 * 24)),
        });
      } catch (err) {
        console.error('[Cloud Status] Qiniu check failed:', err.message);
        return res.json({
          enabled: true,
          provider: config.provider,
          bucket: config.bucket,
          error: err.message,
          nextResetAt: nextReset.toISOString(),
        });
      }
    }

    res.json({
      enabled: true,
      provider: config.provider,
      bucket: config.bucket,
      nextResetAt: nextReset.toISOString(),
    });
  } catch (err) {
    console.error('[Cloud Status] Failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch {}
  return {};
}

function saveSettings(data) {
  ensurePrivateDataDir();
  writePrivateJson(SETTINGS_FILE, data);
}

app.get('/api/settings', requireDeviceAuth, (req, res) => {
  const settings = loadSettings();
  res.json({
    shareSingleUse: settings.shareSingleUse !== false,
  });
});

app.post('/api/settings', requireDeviceAuth, (req, res) => {
  const settings = loadSettings();
  if (typeof req.body?.shareSingleUse === 'boolean') {
    settings.shareSingleUse = req.body.shareSingleUse;
  }
  saveSettings(settings);
  res.json({
    shareSingleUse: settings.shareSingleUse !== false,
  });
});

const SHARE_TOKEN_FILE = path.join(DATA_DIR, 'share-tokens.json');

function loadShareTokens() {
  try {
    if (fs.existsSync(SHARE_TOKEN_FILE)) {
      return JSON.parse(fs.readFileSync(SHARE_TOKEN_FILE, 'utf8'));
    }
  } catch (e) { console.error('[Share] Failed to load tokens:', e.message); }
  return { tokens: {} };
}

function saveShareTokens(data) {
  ensurePrivateDataDir();
  writePrivateJson(SHARE_TOKEN_FILE, data);
}

function generateShareToken() {
  return crypto.randomBytes(16).toString('base64url');
}

// Create share link (requires device auth)
app.post('/api/share/create', requireDeviceAuth, (req, res) => {
  if (process.env.SHARE_ENABLED === 'false') {
    return res.status(403).json({ error: 'Share feature is disabled' });
  }

  const filePath = req.body?.path;
  if (!filePath || typeof filePath !== 'string') {
    return res.status(400).json({ error: 'Missing path' });
  }

  const resolved = resolveSharedEntry(filePath);
  if (!resolved || !resolved.relPath) return res.status(403).json({ error: 'Access denied' });
  if (!fs.existsSync(resolved.fullPath) || !fs.statSync(resolved.fullPath).isFile()) {
    return res.status(404).json({ error: 'File not found' });
  }

  const data = loadShareTokens();
  const token = generateShareToken();

  data.tokens[token] = {
    relPath: resolved.relPath,
    filename: path.basename(resolved.relPath),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    downloadCount: 0,
    maxDownloads: loadSettings().shareSingleUse !== false ? 1 : 50,
  };
  saveShareTokens(data);

  const host = req.get('host') || 'localhost:21891';
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  res.json({ url: `${protocol}://${host}/s/${token}`, token });
});

// Short share link page
app.get('/s/:token', (req, res) => {
  if (process.env.SHARE_ENABLED === 'false') {
    return res.status(403).send('<h1>分享功能已关闭</h1>');
  }
  const data = loadShareTokens();
  const entry = data.tokens[req.params.token];

  if (!entry) return res.status(404).send('<h1>Link not found or expired</h1>');

  const filename = entry.filename || 'download';
  const safeFilename = escapeHtml(filename);
  const dlUrl = `/api/share/${req.params.token}`;

  res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${safeFilename}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #111; color: #ccc; }
  .card { text-align: center; padding: 2rem; }
  h1 { color: #fff; font-size: 1.2rem; margin-bottom: 0.5rem; }
  .filename { color: #34d399; font-weight: 600; word-break: break-all; }
  .size { color: #666; font-size: 0.85rem; margin: 0.5rem 0 1.5rem; }
  .btn { display: inline-block; padding: 0.75rem 2rem; background: #34d399; color: #000; border-radius: 8px; text-decoration: none; font-weight: 600; }
  .btn:hover { background: #2ec08a; }
  .meta { font-size: 0.75rem; color: #555; margin-top: 1rem; }
</style></head><body>
<div class="card">
  <h1>📦 文件分享</h1>
  <p class="filename">${safeFilename}</p>
  <p class="size">一次性下载 · 7 天后过期</p>
  <a class="btn" href="${dlUrl}" download="${safeFilename}">下载文件</a>
  <p class="meta">由 cloudsysncd 分享 · 链接随机生成，仅分享对象可用</p>
</div>
</body></html>`);
});

// Serve shared file (no auth required)
app.get('/api/share/:token', async (req, res) => {
  if (process.env.SHARE_ENABLED === 'false') {
    return res.status(403).json({ error: 'Share feature is disabled' });
  }
  const data = loadShareTokens();
  const entry = data.tokens[req.params.token];

  if (!entry) return res.status(404).json({ error: 'Link not found or expired' });

  const expiresAt = new Date(entry.expiresAt).getTime();
  if (Date.now() > expiresAt) {
    delete data.tokens[req.params.token];
    saveShareTokens(data);
    return res.status(410).json({ error: 'Link has expired' });
  }

  if (entry.downloadCount >= entry.maxDownloads) {
    return res.status(429).json({ error: 'Download limit reached' });
  }

  const resolved = resolveSharedEntry(entry.relPath);
  if (!resolved || !resolved.relPath || !fs.existsSync(resolved.fullPath)) {
    return res.status(404).json({ error: 'File no longer available' });
  }

  entry.downloadCount++;
  entry.lastDownloadedAt = new Date().toISOString();
  saveShareTokens(data);

  const stat = fs.statSync(resolved.fullPath);
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(entry.filename)}`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(stat.size));

  pipeline(fs.createReadStream(resolved.fullPath), res, (err) => {
    if (err) console.error('[Share] Pipeline error:', err.message);
  });
});

const pendingUploads = new Map();

function startSharedDirWatcher() {
  if (!storage.isStorageEnabled()) return;
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });

  const state = loadState();
  if (!state || !state.masterKey) {
    console.log('[Watcher] No master key, skipping auto-upload');
    return;
  }
  const masterKey = Buffer.from(state.masterKey, 'hex');

  fs.watch(sharedDir, (eventType, filename) => {
    if (!filename) return;
    if (filename.startsWith('.')) return;
    if (filename.includes('__pycache__')) return;

    const fullPath = path.join(sharedDir, filename);
    if (!fs.existsSync(fullPath)) return;
    if (fs.lstatSync(fullPath).isSymbolicLink()) return;
    if (fs.statSync(fullPath).isDirectory()) return;
    const relPath = path.relative(sharedDir, fullPath).replace(/\\/g, '/');

    if (HIDDEN_SHARED_RELATIVE_PATHS.has(relPath)) return;
    if (PROTECTED_SHARED_RELATIVE_PATHS.has(relPath)) return;

    if (eventType === 'rename' || eventType === 'change') {
      if (pendingUploads.has(relPath)) {
        clearTimeout(pendingUploads.get(relPath));
      }

      pendingUploads.set(relPath, setTimeout(() => {
        pendingUploads.delete(relPath);
        if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) return;

        console.log(`[Watcher] Auto-uploading: ${relPath}`);
        storage.uploadFileToCloud(DATA_DIR, masterKey, relPath, fullPath)
          .then((result) => {
            if (result) {
              console.log(`[Watcher] Uploaded: ${relPath}`);
            }
          })
          .catch((err) => {
            console.error(`[Watcher] Upload failed for ${relPath}:`, err.message);
          });
      }, 2000));
    }
  });

  console.log(`[Watcher] Watching ${sharedDir} for auto-upload`);
}

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

  if (storage.isStorageEnabled()) {
    storage.cleanupOrphanedObjects(DATA_DIR, sharedDir).catch((err) => {
      console.error('[Storage] Startup cleanup failed:', err.message);
    });
    storage.startPeriodicCleanup(DATA_DIR, sharedDir);
  }

  startSharedDirWatcher();
});
