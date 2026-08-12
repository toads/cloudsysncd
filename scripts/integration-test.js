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

// 单文件下载:body 为 AES-256-GCM 密流,末尾 16 字节为 tag,IV 在响应头
async function downloadPlainFile(baseUrl, requestPath, masterKey, deviceId) {
  const headers = buildAuthHeaders('GET', requestPath, Buffer.alloc(0), masterKey, deviceId);
  const response = await fetch(`${baseUrl}${requestPath}`, { headers });
  if (!response.ok) {
    throw new Error(`GET ${requestPath} -> ${response.status}`);
  }
  const iv = Buffer.from(response.headers.get('x-encrypted-iv'), 'hex');
  const body = Buffer.from(await response.arrayBuffer());
  const tag = body.subarray(body.length - 16);
  const ciphertext = body.subarray(0, body.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function assertNoPlainRelayAccessKey(data, expectedKey) {
  const serialized = JSON.stringify(data);
  if (serialized.includes(expectedKey)) {
    throw new Error('transport config leaked plaintext relay access key');
  }
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

  // 软链接分享夹具:在 shared 外准备文件/目录,以与 share.js --link 相同的方式创建链接并写登记
  const externalDir = path.join(tempRoot, 'external');
  fs.mkdirSync(path.join(externalDir, 'ext-dir'), { recursive: true });
  fs.writeFileSync(path.join(externalDir, 'ext-file.txt'), 'linked external file\n');
  fs.writeFileSync(path.join(externalDir, 'ext-dir', 'inner.txt'), 'linked inner\n');
  fs.writeFileSync(path.join(externalDir, 'secret.txt'), 'unregistered secret\n');

  let linksAvailable = true;
  try {
    const realFile = fs.realpathSync(path.join(externalDir, 'ext-file.txt'));
    const realDir = fs.realpathSync(path.join(externalDir, 'ext-dir'));
    const realSecret = fs.realpathSync(path.join(externalDir, 'secret.txt'));
    fs.symlinkSync(realFile, path.join(sharedDir, 'linked-file.txt'), 'file');
    fs.symlinkSync(realDir, path.join(sharedDir, 'linked-dir'), process.platform === 'win32' ? 'junction' : 'dir');
    // 未登记的越界符号链接:必须保持不可见、不可下载
    fs.symlinkSync(realSecret, path.join(sharedDir, 'secret-link.txt'), 'file');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'shared-links.json'), JSON.stringify({
      'linked-file.txt': realFile,
      'linked-dir': realDir,
    }, null, 2));
  } catch (err) {
    linksAvailable = false;
    console.log(`Skipping shared-link cases (symlink unavailable: ${(err && err.code) || err})`);
  }

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
      CLIENT_PRIMARY_RELAY_URL: 'https://relay.example.test',
      CLIENT_RELAY_ACCESS_KEY: 'integration-relay-access-key',
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

    const transportHeaders = buildAuthHeaders('GET', '/api/transport-config', Buffer.alloc(0), masterKey, deviceId);
    const transportResponse = await fetch(`${baseUrl}/api/transport-config`, { headers: transportHeaders });
    const transportConfig = await transportResponse.json();
    if (!transportResponse.ok) {
      throw new Error(`Unexpected transport config response: ${JSON.stringify(transportConfig)}`);
    }
    assertNoPlainRelayAccessKey(transportConfig, 'integration-relay-access-key');
    if (transportConfig.relayAccessKey !== undefined || !transportConfig.encryptedRelayAccessKey) {
      throw new Error(`Expected encrypted relay access key only: ${JSON.stringify(transportConfig)}`);
    }
    const relayPayload = JSON.parse(decryptAesGcm(masterKey, transportConfig.encryptedRelayAccessKey).toString('utf8'));
    if (relayPayload.relayAccessKey !== 'integration-relay-access-key' || relayPayload.authScheme !== 'hmac-v1') {
      throw new Error(`Unexpected relay transport payload: ${JSON.stringify(relayPayload)}`);
    }

    const devices = await requestJson(`${baseUrl}/api/local/devices`, {
      headers: { 'x-admin-token': adminToken },
    });
    const listed = devices.devices.find((entry) => entry.id === deviceId);
    if (!listed || listed.name !== 'Integration Test') {
      throw new Error(`Device list missing paired device: ${JSON.stringify(devices)}`);
    }

    if (linksAvailable) {
      // 文件列表:已登记链接可见,未登记符号链接不可见
      const filesHeaders = buildAuthHeaders('GET', '/api/files', Buffer.alloc(0), masterKey, deviceId);
      const filesResponse = await fetch(`${baseUrl}/api/files`, { headers: filesHeaders });
      const filesPayload = await filesResponse.json();
      if (!filesResponse.ok) {
        throw new Error(`Unexpected /api/files response: ${JSON.stringify(filesPayload)}`);
      }
      const tree = JSON.parse(decryptAesGcm(masterKey, filesPayload.encrypted).toString('utf8'));
      const entriesByName = new Map(tree.map((entry) => [entry.name, entry]));
      if (entriesByName.get('linked-file.txt')?.type !== 'file') {
        throw new Error(`Registered file link missing from file list: ${JSON.stringify(tree)}`);
      }
      if (entriesByName.get('linked-dir')?.type !== 'dir'
        || entriesByName.get('linked-dir/inner.txt')?.type !== 'file') {
        throw new Error(`Registered dir link missing from file list: ${JSON.stringify(tree)}`);
      }
      if (entriesByName.has('secret-link.txt')) {
        throw new Error('Unregistered symlink must not appear in file list');
      }

      // 下载链接文件,内容必须与源一致
      const linkedFileContent = await downloadPlainFile(baseUrl, '/api/files/linked-file.txt', masterKey, deviceId);
      if (linkedFileContent.toString('utf8') !== 'linked external file\n') {
        throw new Error(`Linked file content mismatch: ${JSON.stringify(linkedFileContent.toString('utf8'))}`);
      }

      // 链接目录内的文件也可下载
      const linkedInnerContent = await downloadPlainFile(baseUrl, '/api/files/linked-dir/inner.txt', masterKey, deviceId);
      if (linkedInnerContent.toString('utf8') !== 'linked inner\n') {
        throw new Error(`Linked dir inner content mismatch: ${JSON.stringify(linkedInnerContent.toString('utf8'))}`);
      }

      // 未登记符号链接:下载必须被拒绝(越界防护照旧生效)
      const secretHeaders = buildAuthHeaders('GET', '/api/files/secret-link.txt', Buffer.alloc(0), masterKey, deviceId);
      const secretResponse = await fetch(`${baseUrl}/api/files/secret-link.txt`, { headers: secretHeaders });
      if (![403, 404].includes(secretResponse.status)) {
        throw new Error(`Expected unregistered symlink download to be rejected, got ${secretResponse.status}`);
      }

      // 已登记链接可正常打包下载(跟随内容)
      const linkArchiveBody = Buffer.from(JSON.stringify({ paths: ['linked-dir'] }));
      const linkArchiveResponse = await fetch(`${baseUrl}/api/archive`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...buildAuthHeaders('POST', '/api/archive', linkArchiveBody, masterKey, deviceId),
        },
        body: linkArchiveBody,
      });
      if (!linkArchiveResponse.ok) {
        throw new Error(`Archive over registered link failed with ${linkArchiveResponse.status}`);
      }
      if ((await linkArchiveResponse.arrayBuffer()).byteLength === 0) {
        throw new Error('Archive over registered link was empty');
      }
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
