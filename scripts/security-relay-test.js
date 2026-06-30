#!/usr/bin/env node
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { setTimeout: delay } = require('timers/promises');
const crypto = require('crypto');

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
      if (response.ok) return await response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
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
  if (child.exitCode === null) child.kill('SIGKILL');
}

function readBodyJson(response) {
  return response.text().then((text) => {
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      return { raw: text };
    }
  });
}

function hmacHex(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function buildRelayAccessHeaders(method, requestPath, bodyBuffer, accessKey, nonce = crypto.randomUUID()) {
  const timestamp = Date.now().toString();
  const bodyHash = sha256Hex(bodyBuffer || Buffer.alloc(0));
  return {
    'X-Relay-Access-Key-Id': 'default',
    'X-Relay-Access-Timestamp': timestamp,
    'X-Relay-Access-Nonce': nonce,
    'X-Relay-Access-Signature': hmacHex(accessKey, [method.toUpperCase(), requestPath, timestamp, nonce, bodyHash].join('\n')),
  };
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsysncd-security-'));
  const dataDir = path.join(root, 'data');
  const sharedDir = path.join(root, 'shared');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(sharedDir, { recursive: true });
  fs.writeFileSync(path.join(sharedDir, 'ok.txt'), 'ok');

  const port = await getFreePort();
  const logs = [];
  const child = spawn(path.resolve(__dirname, '..', 'start.sh'), [], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      SHARED_DIR: sharedDir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => logs.push(chunk.toString()));
  child.stderr.on('data', (chunk) => logs.push(chunk.toString()));
  const getLogs = () => logs.slice(-60).join('');

  try {
    const baseUrl = `http://127.0.0.1:${port}`;
    await waitForHealth(`${baseUrl}/healthz`, child, 10000, getLogs);
    const indexRes = await fetch(`${baseUrl}/`);
    if (!indexRes.ok) throw new Error(`Expected index response, got ${indexRes.status}`);
    const csp = indexRes.headers.get('content-security-policy') || '';
    if (!csp.includes("connect-src 'self'") || csp.includes('connect-src https:') || csp.includes('fonts.googleapis.com')) {
      throw new Error(`Unexpected CSP: ${csp}`);
    }

    const sharePage = await fetch(`${baseUrl}/s/does-not-exist`);
    if (sharePage.status !== 404) {
      throw new Error(`Expected 404 for missing share token, got ${sharePage.status}`);
    }

    const relayPort = await getFreePort();
    const relayKey = 'relay-key-0123456789abcdef';
    const accessKey = 'access-key-0123456789abcdef';
    const relay = spawn('node', ['relay/server.js'], {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...process.env,
        RELAY_PORT: String(relayPort),
        RELAY_KEY: relayKey,
        RELAY_ACCESS_KEY: accessKey,
        RELAY_ACCESS_FORM_ENABLED: 'true',
        RELAY_MAX_REQUEST_BYTES: '1mb',
        RELAY_MAX_JOB_BODY_BYTES: '65536',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const relayLogs = [];
    relay.stdout.on('data', (chunk) => relayLogs.push(chunk.toString()));
    relay.stderr.on('data', (chunk) => relayLogs.push(chunk.toString()));

    try {
      await waitForHealth(`http://127.0.0.1:${relayPort}/__relay/healthz`, relay, 10000, () => relayLogs.join(''));

      const noAuth = await fetch(`http://127.0.0.1:${relayPort}/healthz`);
      if (noAuth.status !== 401) {
        throw new Error(`Expected relay auth failure, got ${noAuth.status}`);
      }

      const loginFail = await fetch(`http://127.0.0.1:${relayPort}/__relay/access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'relay_key=wrong',
      });
      if (loginFail.status !== 401) {
        throw new Error(`Expected login fail 401, got ${loginFail.status}`);
      }

      const loginOk = await fetch(`http://127.0.0.1:${relayPort}/__relay/access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `relay_key=${encodeURIComponent(accessKey)}`,
        redirect: 'manual',
      });
      if (loginOk.status !== 302) {
        throw new Error(`Expected login redirect, got ${loginOk.status}`);
      }
      const localCookie = loginOk.headers.get('set-cookie') || '';
      if (!localCookie || /;\s*Secure/i.test(localCookie)) {
        throw new Error(`Expected local relay cookie without Secure, got ${localCookie}`);
      }

      const loginOkHttps = await fetch(`http://127.0.0.1:${relayPort}/__relay/access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-forwarded-proto': 'https' },
        body: `relay_key=${encodeURIComponent(accessKey)}`,
        redirect: 'manual',
      });
      const tlsCookie = loginOkHttps.headers.get('set-cookie') || '';
      if (loginOkHttps.status !== 302 || !/;\s*Secure/i.test(tlsCookie)) {
        throw new Error(`Expected HTTPS relay cookie with Secure, got ${loginOkHttps.status} ${tlsCookie}`);
      }

      const signedPath = '/api/local/devices';
      const signedHeaders = buildRelayAccessHeaders('GET', signedPath, Buffer.alloc(0), accessKey);
      const signedAuth = await fetch(`http://127.0.0.1:${relayPort}${signedPath}`, {
        headers: signedHeaders,
      });
      if (signedAuth.status !== 403) {
        throw new Error(`Expected signed relay access to pass auth and reach local-admin block, got ${signedAuth.status}`);
      }

      const replayAuth = await fetch(`http://127.0.0.1:${relayPort}${signedPath}`, {
        headers: signedHeaders,
      });
      if (replayAuth.status !== 409) {
        throw new Error(`Expected signed relay replay rejection, got ${replayAuth.status}`);
      }

      const badSignedAuth = await fetch(`http://127.0.0.1:${relayPort}/healthz`, {
        headers: buildRelayAccessHeaders('GET', '/wrong-path', Buffer.alloc(0), accessKey),
      });
      if (badSignedAuth.status !== 401) {
        throw new Error(`Expected invalid signed relay access rejection, got ${badSignedAuth.status}`);
      }

      const bigBody = Buffer.alloc(128 * 1024, 1);
      const discardRes = await fetch(`http://127.0.0.1:${relayPort}/__relay/discard`, {
        method: 'POST',
        headers: { authorization: `Bearer ${relayKey}`, 'content-type': 'application/octet-stream' },
        body: bigBody,
      });
      if (discardRes.status !== 413) {
        throw new Error(`Expected discard body rejection, got ${discardRes.status}`);
      }
    } finally {
      await stopChild(relay);
    }

    console.log('Security relay test passed');
  } finally {
    await stopChild(child);
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
