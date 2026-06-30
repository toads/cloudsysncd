const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { setTimeout: delay } = require('timers/promises');

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close((err) => {
        if (err) return reject(err);
        resolve(address.port);
      });
    });
    server.on('error', reject);
  });
}

async function waitForHealth(url, child, timeoutMs, getLogs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Server exited early with code ${child.exitCode}\n${getLogs()}`);
    }
    try {
      const response = await fetch(url);
      if (!response.ok) {
        lastError = new Error(`Health check returned HTTP ${response.status}`);
      } else {
        return await response.json();
      }
    } catch (error) {
      lastError = error;
    }
    await delay(250);
  }
  throw lastError || new Error(`Timed out waiting for ${url}`);
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  const deadline = Date.now() + 3000;
  while (child.exitCode === null && Date.now() < deadline) {
    await delay(100);
  }
  if (child.exitCode === null) {
    child.kill('SIGKILL');
  }
}

function hkdf(ikm, salt, info, length = 32) {
  return crypto.hkdfSync('sha256', ikm, Buffer.from(salt), Buffer.from(info), length);
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function decryptAesGcm(key, encrypted) {
  const iv = Buffer.from(encrypted.iv, 'hex');
  const ciphertext = Buffer.from(encrypted.ciphertext, 'hex');
  const tag = Buffer.from(encrypted.tag, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  if (!response.ok) {
    throw new Error(`${options.method || 'GET'} ${url} -> ${response.status}\n${text}`);
  }
  return data;
}

function buildAuthHeaders(method, requestPath, bodyBuffer, masterKey, deviceId) {
  const timestamp = Date.now().toString();
  const nonce = crypto.randomUUID();
  const bodyHash = sha256Hex(bodyBuffer);
  const authKey = hkdf(masterKey, 'syncd-request-auth', `device:${deviceId}`, 32);
  const signature = hmac(authKey, [method.toUpperCase(), requestPath, timestamp, nonce, bodyHash].join('\n'));
  return {
    'X-Device-Id': deviceId,
    'X-Auth-Timestamp': timestamp,
    'X-Auth-Nonce': nonce,
    'X-Auth-Signature': signature,
  };
}

async function pair(baseUrl, pin) {
  const init = await requestJson(`${baseUrl}/api/pair/init`);
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const sharedSecret = ecdh.computeSecret(Buffer.from(init.serverPublicKey, 'hex'));
  const authKey = hkdf(sharedSecret, 'syncd-auth', 'pin-verify', 32);
  const proof = hmac(authKey, pin);
  const deviceId = 'test-device';
  const verify = await requestJson(`${baseUrl}/api/pair/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      clientPublicKey: ecdh.getPublicKey('hex'),
      proof,
      deviceId,
      deviceName: 'Chunked Test',
      deviceType: 'node',
    }),
  });
  const expectedServerProof = hmac(authKey, 'server-confirmed');
  if (verify.serverProof !== expectedServerProof) throw new Error('Server proof mismatch');
  const transportKey = hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32);
  const masterKey = decryptAesGcm(transportKey, verify.encryptedMasterKey);
  return { deviceId, masterKey };
}

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'syncd-chunked-test-'));
  const dataDir = path.join(tempRoot, 'data');
  const sharedDir = path.join(tempRoot, 'shared');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(sharedDir, { recursive: true });

  const fileSize = 5 * 1024 * 1024;
  const original = crypto.randomBytes(fileSize);
  fs.writeFileSync(path.join(sharedDir, 'large.bin'), original);

  const port = await getFreePort();
  const logs = [];
  const child = spawn(path.resolve(__dirname, '..', 'start.sh'), [], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      SHARED_DIR: sharedDir,
      PAIR_SESSION_TTL_MS: '10000',
      CHUNKED_THRESHOLD_BYTES: '1048576',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => logs.push(chunk.toString()));
  child.stderr.on('data', (chunk) => logs.push(chunk.toString()));
  const getLogs = () => logs.slice(-50).join('');

  try {
    const baseUrl = `http://127.0.0.1:${port}`;
    const health = await waitForHealth(`${baseUrl}/healthz`, child, 10000, getLogs);
    const adminToken = fs.readFileSync(path.join(dataDir, '.admin-token'), 'utf8').trim();
    const { pin } = await requestJson(`${baseUrl}/api/local/new-pin`, {
      method: 'POST',
      headers: { 'x-admin-token': adminToken },
    });
    const { deviceId, masterKey } = await pair(baseUrl, pin);

    const headers = buildAuthHeaders('GET', '/api/files/large.bin', Buffer.alloc(0), masterKey, deviceId);
    const response = await fetch(`${baseUrl}/api/files/large.bin`, { headers });
    if (!response.ok) throw new Error(`Download failed: ${response.status}`);
    const format = response.headers.get('x-encryption-format');
    if (format !== 'chunked-aead-v1') throw new Error(`Expected chunked-aead-v1, got ${format}`);

    const chunks = [];
    for await (const data of response.body) {
      chunks.push(data);
    }
    const encrypted = Buffer.concat(chunks);

    if (encrypted[0] !== 0x53 || encrypted[1] !== 0x59 || encrypted[2] !== 0x4E || encrypted[3] !== 0x43) {
      throw new Error('Invalid magic');
    }
    const chunkSize = (encrypted[5] << 24) | (encrypted[6] << 16) | (encrypted[7] << 8) | encrypted[8];
    console.log(`Chunk size: ${chunkSize}`);

    let offset = 16;
    const decryptedChunks = [];
    while (offset < encrypted.length) {
      const iv = encrypted.subarray(offset, offset + 12);
      offset += 12;
      const len = (encrypted[offset] << 24) | (encrypted[offset + 1] << 16) | (encrypted[offset + 2] << 8) | encrypted[offset + 3];
      offset += 4;
      const ciphertext = encrypted.subarray(offset, offset + len);
      offset += len;
      const tag = encrypted.subarray(offset, offset + 16);
      offset += 16;
      const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
      decipher.setAuthTag(tag);
      decryptedChunks.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    }
    const decrypted = Buffer.concat(decryptedChunks);
    if (!decrypted.equals(original)) throw new Error('Decrypted content mismatch');
    console.log(`Chunked download test passed: ${decrypted.length} bytes`);
  } finally {
    await stopChild(child);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
