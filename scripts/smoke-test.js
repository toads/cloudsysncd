#!/usr/bin/env node
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
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
        const data = await response.json();
        if (data.ok === true) return data;
        lastError = new Error(`Unexpected health payload: ${JSON.stringify(data)}`);
      }
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
  if (child.exitCode === null) {
    child.kill('SIGKILL');
  }
}

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsysncd-smoke-'));
  const dataDir = path.join(tempRoot, 'data');
  const sharedDir = path.join(tempRoot, 'shared');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(sharedDir, { recursive: true });

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

  const pushLog = (chunk) => {
    logs.push(chunk.toString());
    if (logs.length > 40) logs.shift();
  };
  child.stdout.on('data', pushLog);
  child.stderr.on('data', pushLog);

  const getLogs = () => logs.join('');

  try {
    const health = await waitForHealth(`http://127.0.0.1:${port}/healthz`, child, 10000, getLogs);
    if (health.service !== 'cloudsysncd') {
      throw new Error(`Unexpected service name in health payload: ${JSON.stringify(health)}`);
    }
    console.log(`Smoke test passed on port ${port}`);
  } finally {
    await stopChild(child);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
