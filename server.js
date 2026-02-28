const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { pipeline } = require('stream');
const tar = require('tar');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const MAX_TEXTS = 100;
const TEXT_EXPIRY_MS = 24 * 60 * 60 * 1000;
const CHUNK_SIZE = 1024 * 1024;
const MAX_CONCURRENT_DOWNLOADS = 3;
let activeDownloads = 0;

const DATA_DIR = path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const sharedDir = path.join(__dirname, 'shared');

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

// Master key: generated once, persisted forever
let masterKey = null; // Buffer, 32 bytes
let devices = [];     // [{ id, pairedAt }]

const saved = loadState();
if (saved && saved.masterKey) {
  masterKey = Buffer.from(saved.masterKey, 'hex');
  devices = saved.devices || [];
  console.log(`[STATE] Loaded master key, ${devices.length} paired device(s)`);
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

function decrypt(key, ivHex, ciphertextHex, tagHex) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextHex, 'hex')), decipher.final()]);
}

// ============ Pending Pairing Session ============
// Ephemeral — only lives in memory, one at a time

let pendingPair = null; // { pin, keyPair, attempts, createdAt }

function createPairSession() {
  pendingPair = {
    pin: generatePin(),
    keyPair: generateECDHKeyPair(),
    attempts: 0,
    maxAttempts: 5,
  };
  console.log('\n========================================');
  console.log(`  Pairing PIN: ${pendingPair.pin}`);
  console.log('  Enter this PIN on the remote device');
  console.log('========================================\n');
  return pendingPair.pin;
}

// ============ API: Pairing ============

app.get('/api/status', (req, res) => {
  res.json({ paired: devices.length > 0 });
});

app.get('/api/pair/init', (req, res) => {
  if (!pendingPair) {
    return res.status(400).json({ error: 'No active pairing session. Generate a new PIN on the server.' });
  }
  res.json({ serverPublicKey: pendingPair.keyPair.publicKey });
});

app.post('/api/pair/verify', (req, res) => {
  if (!pendingPair) {
    return res.status(400).json({ error: 'No active pairing session' });
  }
  if (pendingPair.attempts >= pendingPair.maxAttempts) {
    pendingPair = null;
    return res.status(403).json({ error: 'Too many attempts. Generate a new PIN.' });
  }

  const { clientPublicKey, proof, deviceId } = req.body;
  if (!clientPublicKey || !proof) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  pendingPair.attempts++;

  try {
    const sharedSecret = pendingPair.keyPair.ecdh.computeSecret(Buffer.from(clientPublicKey, 'hex'));
    const authKey = Buffer.from(hkdf(sharedSecret, 'syncd-auth', 'pin-verify', 32));

    if (proof !== hmac(authKey, pendingPair.pin)) {
      const remaining = pendingPair.maxAttempts - pendingPair.attempts;
      console.log(`[PAIR] Invalid PIN attempt (${remaining} remaining)`);
      return res.status(401).json({ error: 'Invalid PIN', remaining });
    }

    // PIN verified — encrypt master key with transport key and send to client
    const transportKey = Buffer.from(hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32));
    const encryptedMasterKey = encrypt(transportKey, masterKey);
    const serverProof = hmac(authKey, 'server-confirmed');

    const id = deviceId || 'unknown';
    devices.push({ id, pairedAt: new Date().toISOString() });
    persistDevices();
    pendingPair = null; // Invalidate PIN

    console.log(`[PAIR] Device paired: ${id} (${devices.length} total)`);

    res.json({ success: true, serverProof, encryptedMasterKey });
  } catch (err) {
    console.error('[PAIR] Error:', err.message);
    res.status(500).json({ error: 'Key exchange failed' });
  }
});

// ============ Local-only: Generate new PIN ============

app.post('/api/local/new-pin', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token !== adminToken) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const pin = createPairSession();
  res.json({ pin });
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

app.get('/api/files', (req, res) => {
  if (devices.length === 0) return res.status(403).json({ error: 'Not paired' });
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });
  const tree = walkDir(sharedDir);
  res.json({ encrypted: encrypt(masterKey, Buffer.from(JSON.stringify(tree))) });
});

app.get(/^\/api\/files\/(.*)/, (req, res) => {
  if (devices.length === 0) return res.status(403).json({ error: 'Not paired' });
  
  const relPath = req.params[0] || '';
  const filePath = path.resolve(path.join(sharedDir, relPath));
  if (!filePath.startsWith(path.resolve(sharedDir))) return res.status(403).json({ error: 'Access denied' });
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return res.status(404).json({ error: 'Not found' });
  
  const stat = fs.statSync(filePath);
  const fileSize = stat.size;
  
  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }
  
  if (fileSize > CHUNK_SIZE) {
    activeDownloads++;
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-File-Size', fileSize);
    
    const { cipher, iv } = createEncryptStream(masterKey);
    const fileStream = fs.createReadStream(filePath);
    
    let chunks = [];
    cipher.on('data', chunk => chunks.push(chunk));
    
    pipeline(fileStream, cipher, (err) => {
      activeDownloads--;
      if (err) {
        console.error('[FILE] Stream error:', err.message);
        if (!res.headersSent) res.status(500).json({ error: 'Encryption failed' });
        return;
      }
      
      const encrypted = Buffer.concat(chunks);
      const tag = cipher.getAuthTag();
      res.json({
        encrypted: {
          iv: iv.toString('hex'),
          ciphertext: encrypted.toString('hex'),
          tag: tag.toString('hex'),
          filename: path.basename(relPath),
          size: fileSize
        }
      });
    });
  } else {
    const content = fs.readFileSync(filePath);
    const enc = encrypt(masterKey, content);
    enc.filename = path.basename(relPath);
    enc.size = content.length;
    res.json({ encrypted: enc });
  }
});

// ============ Batch Download ============

app.get('/api/batch', (req, res) => {
  if (devices.length === 0) return res.status(403).json({ error: 'Not paired' });
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });

  const since = req.query.since ? new Date(req.query.since) : null;

  const files = [];
  let totalSize = 0;
  for (const entry of walkDir(sharedDir)) {
    if (entry.type !== 'file') continue;
    if (since && new Date(entry.modified) <= since) continue;
    files.push(entry.name);
    totalSize += entry.size;
  }

  if (files.length === 0) {
    return res.json({ encrypted: null, count: 0, totalSize: 0 });
  }

  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  const { cipher, iv } = createEncryptStream(masterKey);
  const tarStream = tar.create({ gzip: true, cwd: sharedDir }, files);
  
  let chunks = [];
  cipher.on('data', chunk => chunks.push(chunk));
  
  pipeline(tarStream, cipher, (err) => {
    activeDownloads--;
    if (err) {
      console.error('[BATCH] Stream error:', err.message);
      if (!res.headersSent) res.status(500).json({ error: 'Archive failed' });
      return;
    }
    
    const encrypted = Buffer.concat(chunks);
    const tag = cipher.getAuthTag();
    res.json({
      encrypted: {
        iv: iv.toString('hex'),
        ciphertext: encrypted.toString('hex'),
        tag: tag.toString('hex')
      },
      count: files.length,
      totalSize
    });
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
  }
}

app.post('/api/text', (req, res) => {
  if (devices.length === 0) return res.status(403).json({ error: 'Not paired' });
  const { encryptedText } = req.body;
  if (!encryptedText) return res.status(400).json({ error: 'Missing encryptedText' });
  
  cleanExpiredTexts();
  
  if (sharedTexts.length >= MAX_TEXTS) {
    sharedTexts.shift();
  }
  
  sharedTexts.push({ id: crypto.randomUUID(), data: encryptedText, timestamp: new Date().toISOString() });
  console.log(`[TEXT] New encrypted text (${sharedTexts.length} total)`);
  res.json({ success: true });
});

app.get('/api/texts', (req, res) => {
  if (devices.length === 0) return res.status(403).json({ error: 'Not paired' });
  cleanExpiredTexts();
  res.json({ texts: sharedTexts });
});

// ============ Start Server ============

const PORT = process.env.PORT || 21891;
app.listen(PORT, () => {
  console.log(`syncd server running on http://localhost:${PORT}`);
  console.log(`Shared directory: ${sharedDir}`);
  console.log(`Paired devices: ${devices.length}`);
  if (devices.length === 0) {
    createPairSession();
  } else {
    console.log('\nReady. Run `node pin.js` to generate a PIN for a new device.\n');
  }
});