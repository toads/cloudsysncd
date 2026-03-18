#!/usr/bin/env node
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
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
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
      deviceName: 'Integration Test',
      deviceType: 'node',
    }),
  });

  const expectedServerProof = hmac(authKey, 'server-confirmed');
  if (verify.serverProof !== expectedServerProof) {
    throw new Error('Server proof mismatch');
  }

  const transportKey = hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32);
  const masterKey = decryptAesGcm(transportKey, verify.encryptedMasterKey);
  return { deviceId, masterKey };
}

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsysncd-integration-'));
  const dataDir = path.join(tempRoot, 'data');
  const sharedDir = path.join(tempRoot, 'shared');
  fs.mkdirSync(path.join(sharedDir, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(sharedDir, 'alpha.txt'), 'hello alpha\n');
  fs.writeFileSync(path.join(sharedDir, 'docs', 'note.txt'), 'nested\n');

  const port = await getFreePort();
  const logs = [];
  const child = spawn(path.resolve(__dirname, '..', 'start.sh'), [], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      SHARED_DIR: sharedDir,
      PAIR_SESSION_TTL_MS: '1000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => logs.push(chunk.toString()));
  child.stderr.on('data', (chunk) => logs.push(chunk.toString()));
  const getLogs = () => logs.slice(-50).join('');

  try {
    const baseUrl = `http://127.0.0.1:${port}`;
    const health = await waitForHealth(`${baseUrl}/healthz`, child, 10000, getLogs);
    if (!health.ok || !health.pendingPairExpiresAt) {
      throw new Error(`Unexpected health payload: ${JSON.stringify(health)}`);
    }

    await delay(1200);
    const expiredStatus = await requestJson(`${baseUrl}/api/pair/status`);
    if (expiredStatus.active) {
      throw new Error('Pairing session should expire during integration test');
    }

    const adminToken = fs.readFileSync(path.join(dataDir, '.admin-token'), 'utf8').trim();
    const newPin = await requestJson(`${baseUrl}/api/local/new-pin`, {
      method: 'POST',
      headers: { 'x-admin-token': adminToken },
    });
    if (!newPin.pin || !newPin.expiresAt) {
      throw new Error('Expected admin new-pin response to include pin and expiresAt');
    }

    const { deviceId, masterKey } = await pair(baseUrl, newPin.pin);
    const sessionHeaders = buildAuthHeaders('GET', '/api/session', Buffer.alloc(0), masterKey, deviceId);
    const sessionResponse = await fetch(`${baseUrl}/api/session`, { headers: sessionHeaders });
    const session = await sessionResponse.json();
    if (!sessionResponse.ok || session.device?.name !== 'Integration Test') {
      throw new Error(`Unexpected session payload: ${JSON.stringify(session)}`);
    }

    const devices = await requestJson(`${baseUrl}/api/local/devices`, {
      headers: { 'x-admin-token': adminToken },
    });
    const listed = devices.devices.find((entry) => entry.id === deviceId);
    if (!listed || listed.name !== 'Integration Test') {
      throw new Error(`Device list missing paired device: ${JSON.stringify(devices)}`);
    }

    const archiveBody = Buffer.from(JSON.stringify({ paths: ['alpha.txt', 'docs'] }));
    const archiveHeaders = {
      'Content-Type': 'application/json',
      ...buildAuthHeaders('POST', '/api/archive', archiveBody, masterKey, deviceId),
    };
    const archiveResponse = await fetch(`${baseUrl}/api/archive`, {
      method: 'POST',
      headers: archiveHeaders,
      body: archiveBody,
    });
    if (!archiveResponse.ok) {
      throw new Error(`Archive request failed with ${archiveResponse.status}`);
    }
    if (archiveResponse.headers.get('x-archive-count') !== '2') {
      throw new Error(`Unexpected archive headers: ${archiveResponse.headers.get('x-archive-count')}`);
    }
    const archiveBytes = await archiveResponse.arrayBuffer();
    if (archiveBytes.byteLength === 0) {
      throw new Error('Archive response was empty');
    }

    await requestJson(`${baseUrl}/api/local/devices/${deviceId}`, {
      method: 'DELETE',
      headers: { 'x-admin-token': adminToken },
    });

    const revokedHeaders = buildAuthHeaders('GET', '/api/session', Buffer.alloc(0), masterKey, deviceId);
    const revokedResponse = await fetch(`${baseUrl}/api/session`, { headers: revokedHeaders });
    if (revokedResponse.status !== 401) {
      throw new Error(`Expected revoked device to fail with 401, got ${revokedResponse.status}`);
    }

    console.log(`Integration test passed on port ${port}`);
  } finally {
    await stopChild(child);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
