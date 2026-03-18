#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 21891;

function resolveDataDir() {
  if (process.env.DATA_DIR) {
    return path.resolve(process.env.DATA_DIR);
  }

  const localDir = path.join(__dirname, 'data');
  const dockerDir = path.join(__dirname, '.local', 'data');
  const localToken = path.join(localDir, '.admin-token');
  const dockerToken = path.join(dockerDir, '.admin-token');

  if (!fs.existsSync(localToken) && fs.existsSync(dockerToken)) {
    return dockerDir;
  }
  return localDir;
}

function readAdminToken() {
  const dataDir = resolveDataDir();
  const tokenFile = path.join(dataDir, '.admin-token');
  try {
    return fs.readFileSync(tokenFile, 'utf8').trim();
  } catch {
    console.error('Cannot read admin token. Is the server running?');
    process.exit(1);
  }
}

function usage() {
  console.log('用法:');
  console.log('  node pin.js                 生成新的配对 PIN');
  console.log('  node pin.js --devices       查看已配对设备');
  console.log('  node pin.js --revoke <id>   撤销某个设备');
}

function formatRemaining(expiresAt) {
  const ms = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return '已过期';
  const totalSeconds = Math.ceil(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

async function request(pathname, options = {}) {
  const token = readAdminToken();
  const response = await fetch(`http://127.0.0.1:${PORT}${pathname}`, {
    ...options,
    headers: {
      'x-admin-token': token,
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }

  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

function printDevices(devices) {
  if (!Array.isArray(devices) || devices.length === 0) {
    console.log('\nNo paired devices.\n');
    return;
  }

  console.log('');
  for (const device of devices) {
    const state = device.active ? 'active' : `revoked at ${device.revokedAt}`;
    console.log(`- ${device.id}`);
    console.log(`  name: ${device.name}`);
    console.log(`  type: ${device.type}`);
    console.log(`  pairedAt: ${device.pairedAt}`);
    console.log(`  lastSeenAt: ${device.lastSeenAt || 'never'}`);
    console.log(`  state: ${state}`);
  }
  console.log('');
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    usage();
    return;
  }

  if (args[0] === '--devices') {
    const data = await request('/api/local/devices');
    printDevices(data.devices);
    return;
  }

  if (args[0] === '--revoke') {
    const deviceId = args[1];
    if (!deviceId) {
      usage();
      process.exit(1);
    }
    const data = await request(`/api/local/devices/${encodeURIComponent(deviceId)}`, {
      method: 'DELETE',
    });
    console.log(`\nRevoked device: ${data.device.id}\n`);
    return;
  }

  if (args.length > 0) {
    usage();
    process.exit(1);
  }

  const data = await request('/api/local/new-pin', { method: 'POST' });
  if (!data.pin) {
    throw new Error('Server did not return a PIN');
  }

  console.log(`\nNew pairing PIN: ${data.pin}`);
  if (data.expiresAt) {
    console.log(`Expires at: ${data.expiresAt} (${formatRemaining(data.expiresAt)})`);
  }
  if (typeof data.attemptsRemaining === 'number') {
    console.log(`Attempts remaining: ${data.attemptsRemaining}`);
  }
  console.log('');
}

main().catch((err) => {
  console.error(err.message || 'Server not running?');
  process.exit(1);
});
