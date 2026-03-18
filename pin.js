#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 21891;
const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const tokenFile = path.join(dataDir, '.admin-token');

let token;
try {
  token = fs.readFileSync(tokenFile, 'utf8').trim();
} catch {
  console.error('Cannot read admin token. Is the server running?');
  process.exit(1);
}

fetch(`http://127.0.0.1:${PORT}/api/local/new-pin`, {
  method: 'POST',
  headers: { 'x-admin-token': token },
})
  .then(async (r) => {
    const text = await r.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {};
    }

    if (!r.ok) {
      throw new Error(data.error || `HTTP ${r.status}`);
    }
    return data;
  })
  .then(data => {
    if (data.pin) console.log(`\nNew pairing PIN: ${data.pin}\n`);
    else {
      console.error('Error:', data.error || 'Unknown error');
      process.exit(1);
    }
  })
  .catch((err) => {
    console.error(err.message || 'Server not running?');
    process.exit(1);
  });
