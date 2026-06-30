#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { setTimeout: delay } = require('timers/promises');
const { pipeline } = require('stream/promises');

const FILE_SIZE = Number.parseInt(process.env.RELAY_E2E_FILE_SIZE || String(8 * 1024 * 1024), 10);
const CHUNK_SIZE = 1024 * 1024;
const RELAY_AGENT_ENV_PATH = process.env.RELAY_AGENT_ENV || path.resolve(__dirname, '..', '.relay-agent.env');
const RELAY_CLIENT_ENV_PATH = process.env.RELAY_CLIENT_ENV || path.resolve(__dirname, '..', '.relay-client.env');
const LAUNCHD_LABEL = process.env.RELAY_E2E_LAUNCHD_LABEL || 'com.cloudsysncd.relay-agent';
const MANAGE_LAUNCHD = process.env.RELAY_E2E_MANAGE_LAUNCHD === 'true';
const RELAY_E2E_REQUIRED = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.RELAY_E2E_REQUIRED || '').trim().toLowerCase()
);
const RELAY_E2E_USE_ENV_FILES = RELAY_E2E_REQUIRED || ['1', 'true', 'yes', 'on'].includes(
  String(process.env.RELAY_E2E_USE_ENV_FILES || '').trim().toLowerCase()
);

let serverChild = null;
let agentChild = null;
let DATA_DIR = null;
let SHARED_DIR = null;
let CLIENT_DIR = null;
let launchdWasLoaded = false;

function parseDotEnv(filePath) {
  const result = {};
  if (!fs.existsSync(filePath)) return result;
  for (const rawLine of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index <= 0) continue;
    const key = line.slice(0, index).trim();
    let value = line.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

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

function runCommand(command, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: options.cwd || path.resolve(__dirname, '..'),
      env: { ...process.env, ...options.env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
    child.on('error', (err) => resolve({ code: -1, stdout: '', stderr: err.message }));
  });
}

async function waitForHealth(url, timeoutMs, options = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, {
        headers: options.headers || undefined,
      });
      if (response.ok) return await response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
    }
    await delay(250);
  }
  throw lastError || new Error(`Health check timeout: ${url}`);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  if (!response.ok) throw new Error(`${options.method || 'GET'} ${url} -> ${response.status}\n${text}`);
  return data;
}

function runNode(args, options = {}) {
  return runCommand(process.execPath, args, {
    cwd: path.resolve(__dirname, '..'),
    env: options.env || {},
  });
}

function hmacHex(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function buildRelayAccessHeaders(method, requestPath, bodyBuffer, accessKey) {
  const timestamp = Date.now().toString();
  const nonce = crypto.randomUUID();
  const bodyHash = sha256Hex(bodyBuffer || Buffer.alloc(0));
  return {
    'X-Relay-Access-Key-Id': 'default',
    'X-Relay-Access-Timestamp': timestamp,
    'X-Relay-Access-Nonce': nonce,
    'X-Relay-Access-Signature': hmacHex(accessKey, [method.toUpperCase(), requestPath, timestamp, nonce, bodyHash].join('\n')),
  };
}

function runPython(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', args, {
      cwd: options.cwd || path.resolve(__dirname, '..'),
      env: { ...process.env, ...options.env },
      stdio: options.stdin ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
    });
    if (options.stdin && child.stdin) {
      child.stdin.write(options.stdin);
      child.stdin.end();
    }
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
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
  await pipeline(fs.createReadStream(filePath), hash);
  return hash.digest('hex');
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

function skipOrThrow(message) {
  if (RELAY_E2E_REQUIRED) throw new Error(message);
  console.log(`TX relay E2E skipped: ${message}`);
  console.log('Set RELAY_E2E_REQUIRED=true to make missing relay configuration fail the run.');
}

async function stopChild(child, name) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  const deadline = Date.now() + 5000;
  while (child.exitCode === null && Date.now() < deadline) {
    await delay(200);
  }
  if (child.exitCode === null) {
    console.warn(`${name} did not stop gracefully; sending SIGKILL`);
    child.kill('SIGKILL');
  }
}

async function isLaunchdLoaded() {
  if (!MANAGE_LAUNCHD) return false;
  const result = await runCommand('launchctl', ['print', `gui/${process.getuid()}/${LAUNCHD_LABEL}`]);
  return result.code === 0;
}

async function stopLaunchdAgentIfNeeded() {
  launchdWasLoaded = await isLaunchdLoaded();
  if (!launchdWasLoaded) return;

  console.log(`Temporarily unloading launchd agent: ${LAUNCHD_LABEL}`);
  const plist = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCHD_LABEL}.plist`);
  const result = await runCommand('launchctl', ['bootout', `gui/${process.getuid()}`, plist]);
  if (result.code !== 0) {
    throw new Error(`launchctl bootout failed: ${result.stderr || result.stdout}`);
  }
  await delay(1000);
}

async function restoreLaunchdAgentIfNeeded() {
  if (!launchdWasLoaded || !MANAGE_LAUNCHD) return;
  const plist = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCHD_LABEL}.plist`);
  console.log(`Restoring launchd agent: ${LAUNCHD_LABEL}`);
  const result = await runCommand('launchctl', ['bootstrap', `gui/${process.getuid()}`, plist]);
  if (result.code !== 0) {
    console.error(`launchctl bootstrap failed: ${result.stderr || result.stdout}`);
  }
}

async function startServer(port) {
  const rootDir = path.resolve(__dirname, '..');
  const logs = [];
  serverChild = spawn(path.join(rootDir, 'start.sh'), [], {
    cwd: rootDir,
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR,
      SHARED_DIR,
      PAIR_SESSION_TTL_MS: '60000',
      CHUNKED_THRESHOLD_BYTES: '1048576',
      STORAGE_PROVIDER: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  serverChild.stdout.on('data', (chunk) => {
    const text = chunk.toString('utf8');
    logs.push(text);
    if (text.includes('Pairing PIN')) console.log('[server]', text.trim());
  });
  serverChild.stderr.on('data', (chunk) => {
    const text = chunk.toString('utf8');
    logs.push(text);
    if (/error/i.test(text)) console.error('[server]', text.trim());
  });

  await waitForHealth(`http://127.0.0.1:${port}/healthz`, 10000);
  console.log(`Local origin ready on port ${port}`);
}

async function startRelayAgent(relayUrl, relayKey, originUrl) {
  const rootDir = path.resolve(__dirname, '..');
  agentChild = spawn(process.execPath, ['relay/agent.js'], {
    cwd: rootDir,
    env: {
      ...process.env,
      RELAY_AGENT_ENV: '/dev/null',
      RELAY_URL: relayUrl,
      RELAY_KEY: relayKey,
      ORIGIN_URL: originUrl,
      RELAY_WORKERS: '2',
      RELAY_IDLE_DELAY_MS: '200',
      RELAY_ERROR_DELAY_MS: '1000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  agentChild.stdout.on('data', (chunk) => {
    const text = chunk.toString('utf8').trim();
    if (text) console.log('[agent]', text);
  });
  agentChild.stderr.on('data', (chunk) => {
    const text = chunk.toString('utf8').trim();
    if (text) console.error('[agent]', text);
  });

  await delay(1500);
  if (agentChild.exitCode !== null) {
    throw new Error(`relay agent exited early with code ${agentChild.exitCode}`);
  }
}

async function main() {
  const hasExplicitConfig = !!(
    process.env.RELAY_E2E_URL
    || process.env.RELAY_E2E_KEY
    || process.env.RELAY_E2E_ACCESS_KEY
  );
  if (!RELAY_E2E_REQUIRED && !RELAY_E2E_USE_ENV_FILES && !hasExplicitConfig) {
    skipOrThrow('explicit relay config not enabled. Set RELAY_E2E_URL/KEY/ACCESS_KEY or RELAY_E2E_USE_ENV_FILES=true.');
    return;
  }

  const agentEnv = RELAY_E2E_USE_ENV_FILES ? parseDotEnv(RELAY_AGENT_ENV_PATH) : {};
  const clientEnv = RELAY_E2E_USE_ENV_FILES ? parseDotEnv(RELAY_CLIENT_ENV_PATH) : {};
  const relayUrl = (process.env.RELAY_E2E_URL || agentEnv.RELAY_URL || clientEnv.SYNCD_SERVER || '').replace(/\/+$/, '');
  const relayKey = process.env.RELAY_E2E_KEY || agentEnv.RELAY_KEY || '';
  const relayAccessKey = process.env.RELAY_E2E_ACCESS_KEY || clientEnv.SYNCD_RELAY_ACCESS_KEY || '';

  const missing = [];
  if (!relayUrl) missing.push(`relay URL (set RELAY_E2E_URL or ${RELAY_AGENT_ENV_PATH})`);
  if (!relayKey || relayKey.length < 16) missing.push('relay agent key with at least 16 characters');
  if (!relayAccessKey) missing.push(`relay access key (set RELAY_E2E_ACCESS_KEY or ${RELAY_CLIENT_ENV_PATH})`);
  if (missing.length > 0) {
    skipOrThrow(missing.join(', '));
    return;
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'syncd-relay-e2e-'));
  DATA_DIR = path.join(tempRoot, 'data');
  SHARED_DIR = path.join(tempRoot, 'shared');
  CLIENT_DIR = path.join(tempRoot, 'client');
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(SHARED_DIR, { recursive: true });
  fs.mkdirSync(CLIENT_DIR, { recursive: true });

  const originalFile = path.join(tempRoot, 'relay-source.bin');
  console.log(`Generating ${Math.round(FILE_SIZE / 1024 / 1024)}MB random file...`);
  await generateRandomFile(originalFile, FILE_SIZE);
  const originalHash = await sha256File(originalFile);
  console.log(`Original SHA-256: ${originalHash}`);

  const port = await getFreePort();
  const originUrl = `http://127.0.0.1:${port}`;

  try {
    await stopLaunchdAgentIfNeeded();
    await startServer(port);

    console.log(`Checking TX relay: ${relayUrl}`);
    await waitForHealth(`${relayUrl}/__relay/healthz`, 10000);
    await startRelayAgent(relayUrl, relayKey, originUrl);

    console.log('Checking origin health through TX relay...');
    const healthPath = '/healthz';
    const relayHealth = await waitForHealth(`${relayUrl}/healthz`, 30000, {
      headers: buildRelayAccessHeaders('GET', healthPath, Buffer.alloc(0), relayAccessKey),
    });
    if (!relayHealth.ok || relayHealth.service !== 'cloudsysncd') {
      throw new Error(`Unexpected relayed health payload: ${JSON.stringify(relayHealth)}`);
    }

    console.log('Requesting local PIN...');
    const adminToken = fs.readFileSync(path.join(DATA_DIR, '.admin-token'), 'utf8').trim();
    const newPin = await requestJson(`${originUrl}/api/local/new-pin`, {
      method: 'POST',
      headers: { 'x-admin-token': adminToken },
    });
    const pin = newPin.pin;

    console.log('Sharing file into local origin...');
    const shareResult = await runNode(['share.js', originalFile], {
      env: { DATA_DIR, SHARED_DIR, STORAGE_PROVIDER: 'false' },
    });
    if (shareResult.code !== 0) {
      throw new Error(`share.js failed with code ${shareResult.code}\n${shareResult.stderr}`);
    }

    console.log('Running Python CLI through TX relay...');
    const pythonResult = await runPython([
      path.resolve(__dirname, '..', 'shared', 'sync_download.py'),
      '--once',
      '--dir', CLIENT_DIR,
      '--state-dir', CLIENT_DIR,
      '--device-name', 'tx-relay-e2e',
      '--relay-access-key', relayAccessKey,
    ], {
      env: {
        SYNCD_SERVER: relayUrl,
        SYNCD_VERIFY_TLS: process.env.RELAY_E2E_VERIFY_TLS || 'true',
      },
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
    if (downloadedHash !== originalHash) {
      throw new Error('SHA-256 mismatch');
    }

    console.log('\nTX relay E2E passed');
    console.log(`  Relay: ${relayUrl}`);
    console.log(`  File size: ${Math.round(FILE_SIZE / 1024 / 1024)}MB`);
    console.log('  Path: Python CLI -> TX HTTPS relay -> local relay agent -> local syncd origin');
    console.log(`  SHA-256 verified: ${originalHash}`);
  } finally {
    await stopChild(agentChild, 'relay agent');
    await stopChild(serverChild, 'local origin');
    await restoreLaunchdAgentIfNeeded();
    fs.rmSync(tempRoot, { recursive: true, force: true });
    console.log('Cleaned up temp directory.');
  }
}

main().catch((err) => {
  console.error('\nTX relay E2E failed:', err.message || err);
  Promise.resolve()
    .then(() => stopChild(agentChild, 'relay agent'))
    .then(() => stopChild(serverChild, 'local origin'))
    .then(() => restoreLaunchdAgentIfNeeded())
    .finally(() => process.exit(1));
});
