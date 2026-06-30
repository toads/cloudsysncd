#!/usr/bin/env node
/**
 * Qiniu E2E test - runs with actual Qiniu credentials
 * Usage: node scripts/e2e-qiniu.js
 * Requires: QINIU_ACCESS_KEY, QINIU_SECRET_KEY, QINIU_BUCKET env vars
 */
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { setTimeout: delay } = require('timers/promises');
const { pipeline } = require('stream/promises');

const FILE_SIZE = 5 * 1024 * 1024; // 5MB for quick Qiniu test
const CHUNK_SIZE = 1024 * 1024;

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

async function waitForHealth(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return await response.json();
    } catch {}
    await delay(250);
  }
  throw new Error('Health check timeout');
}

function runNode(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: path.resolve(__dirname, '..'),
      env: { ...process.env, ...options.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (c) => stdout.push(c));
    child.stderr.on('data', (c) => stderr.push(c));
    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
    child.on('error', reject);
  });
}

function runPython(args, options = {}) {
  return new Promise((resolve, reject) => {
    const stdio = options.stdio ? options.stdio : (options.stdin ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe']);
    const child = spawn('python3', args, {
      cwd: options.cwd || path.resolve(__dirname, '..'),
      env: { ...process.env, ...options.env },
      stdio,
    });
    if (options.stdin && child.stdin) {
      child.stdin.write(options.stdin);
      child.stdin.end();
    }
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (c) => stdout.push(c));
    child.stderr.on('data', (c) => stderr.push(c));
    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
    child.on('error', reject);
  });
}

async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const stream = fs.createReadStream(filePath);
  await pipeline(stream, hash);
  return hash.digest('hex');
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  if (!response.ok) throw new Error(`${options.method || 'GET'} ${url} -> ${response.status}\n${text}`);
  return data;
}

let serverChild = null;
let DATA_DIR = null;
let SHARED_DIR = null;
let CLIENT_DIR = null;

async function startServer(port, envOverrides = {}) {
  const rootDir = path.resolve(__dirname, '..');
  serverChild = spawn(path.join(rootDir, 'start.sh'), [], {
    cwd: rootDir,
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR,
      SHARED_DIR,
      PAIR_SESSION_TTL_MS: '60000',
      CHUNKED_THRESHOLD_BYTES: '1048576',
      STORAGE_FALLBACK_BYTES: '1', // Force cloud for all files
      ...envOverrides,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  serverChild.stdout.on('data', (c) => {
    const line = c.toString('utf8');
    if (line.includes('Pairing PIN')) console.log('[server]', line.trim());
  });
  serverChild.stderr.on('data', (c) => {
    const line = c.toString('utf8');
    if (line.includes('error') || line.includes('Error')) console.error('[server]', line.trim());
  });

  await waitForHealth(`http://127.0.0.1:${port}/healthz`, 10000);
  console.log(`Server ready on port ${port}`);
}

async function stopServer() {
  if (!serverChild || serverChild.exitCode !== null) return;
  serverChild.kill('SIGTERM');
  const deadline = Date.now() + 5000;
  while (serverChild.exitCode === null && Date.now() < deadline) {
    await delay(200);
  }
  if (serverChild.exitCode === null) serverChild.kill('SIGKILL');
}

async function main() {
  // Check Qiniu credentials
  const qiniuAK = process.env.QINIU_ACCESS_KEY;
  const qiniuSK = process.env.QINIU_SECRET_KEY;
  const qiniuBucket = process.env.QINIU_BUCKET;

  if (!qiniuAK || !qiniuSK || !qiniuBucket) {
    console.error('❌ Missing Qiniu credentials. Set QINIU_ACCESS_KEY, QINIU_SECRET_KEY, QINIU_BUCKET');
    process.exit(1);
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'syncd-qiniu-e2e-'));
  DATA_DIR = path.join(tempRoot, 'data');
  SHARED_DIR = path.join(tempRoot, 'shared');
  CLIENT_DIR = path.join(tempRoot, 'client');

  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(SHARED_DIR, { recursive: true });
  fs.mkdirSync(CLIENT_DIR, { recursive: true });

  const originalFile = path.join(tempRoot, 'source.bin');
  console.log(`Generating ${FILE_SIZE / 1024 / 1024}MB random file...`);
  await generateRandomFile(originalFile, FILE_SIZE);
  const originalHash = await sha256File(originalFile);
  console.log(`Original SHA-256: ${originalHash}`);

  const port = await getFreePort();
  console.log(`Starting server on port ${port} with Qiniu cloud storage...`);
  await startServer(port, {
    STORAGE_PROVIDER: 'qiniu',
    QINIU_ACCESS_KEY: qiniuAK,
    QINIU_SECRET_KEY: qiniuSK,
    QINIU_BUCKET: qiniuBucket,
    QINIU_ENDPOINT: process.env.QINIU_ENDPOINT || 'https://s3-cn-east-1.qiniucs.com',
  });

  try {
    const baseUrl = `http://127.0.0.1:${port}`;
    console.log('Requesting PIN...');
    const adminToken = fs.readFileSync(path.join(DATA_DIR, '.admin-token'), 'utf8').trim();
    const newPin = await requestJson(`${baseUrl}/api/local/new-pin`, {
      method: 'POST',
      headers: { 'x-admin-token': adminToken },
    });
    const pin = newPin.pin;
    console.log(`PIN: ${pin}`);

    console.log('Sharing file via share.js (should auto-upload to Qiniu)...');
    const shareResult = await runNode([
      'share.js',
      originalFile,
    ], { env: { DATA_DIR, SHARED_DIR } });
    if (shareResult.code !== 0) {
      console.error('share.js stderr:', shareResult.stderr);
      throw new Error(`share.js failed with code ${shareResult.code}`);
    }
    console.log('share.js output:', shareResult.stdout.split('\n').filter(Boolean).pop());

    // Wait a bit for async upload to complete
    console.log('Waiting for Qiniu upload to complete...');
    await delay(5000);

    console.log('Running Python CLI to download...');
    const pythonEnv = {
      SYNCD_SERVER: baseUrl,
      SYNCD_VERIFY_TLS: 'false',
    };

    const pythonResult = await runPython([
      path.resolve(__dirname, '..', 'shared', 'sync_download.py'),
      '--once',
      '--dir', CLIENT_DIR,
      '--state-dir', CLIENT_DIR,
      '--device-name', 'qiniu-e2e-test',
    ], {
      env: pythonEnv,
      stdin: `${pin}\n`,
    });

    console.log('Python stdout:', pythonResult.stdout);
    if (pythonResult.stderr) console.log('Python stderr:', pythonResult.stderr);
    if (pythonResult.code !== 0) {
      throw new Error(`Python CLI failed with code ${pythonResult.code}`);
    }

    const downloadedFile = path.join(CLIENT_DIR, path.basename(originalFile));
    if (!fs.existsSync(downloadedFile)) {
      throw new Error(`Downloaded file not found: ${downloadedFile}`);
    }
    const downloadedHash = await sha256File(downloadedFile);
    console.log(`Downloaded SHA-256: ${downloadedHash}`);

    if (originalHash !== downloadedHash) {
      throw new Error('SHA-256 mismatch!');
    }

    console.log('\n✅ Qiniu E2E test passed:');
    console.log(`   File size: ${FILE_SIZE / 1024 / 1024}MB`);
    console.log(`   Provider: Qiniu (${qiniuBucket})`);
    console.log(`   SHA-256 verified: ${originalHash}`);
  } finally {
    await stopServer();
    fs.rmSync(tempRoot, { recursive: true, force: true });
    console.log('Cleaned up temp directory.');
  }
}

async function generateRandomFile(filePath, size) {
  const chunk = crypto.randomBytes(CHUNK_SIZE);
  const handle = fs.openSync(filePath, 'w');
  try {
    for (let written = 0; written < size; written += CHUNK_SIZE) {
      const toWrite = Math.min(CHUNK_SIZE, size - written);
      fs.writeSync(handle, chunk.subarray(0, toWrite));
    }
  } finally {
    fs.closeSync(handle);
  }
}

main().catch((err) => {
  console.error('\n❌ Qiniu E2E test failed:', err.message);
  try {
    if (serverChild) serverChild.kill('SIGKILL');
  } catch {}
  process.exit(1);
});
