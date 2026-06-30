const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.STORAGE_FALLBACK_BYTES = '1';

const storage = require('../lib/cloud-storage');
const chunkedAead = require('../lib/chunked-aead');

async function main() {
  if (!storage.isStorageEnabled()) {
    console.error('Cloud storage not enabled. Set STORAGE_PROVIDER=r2|qiniu and required credentials.');
    process.exit(1);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syncd-cloud-test-'));
  const dataDir = path.join(tmpDir, 'data');
  const sharedDir = path.join(tmpDir, 'shared');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(sharedDir, { recursive: true });

  const masterKey = crypto.randomBytes(32);
  const stateFile = path.join(dataDir, 'state.json');
  fs.writeFileSync(stateFile, JSON.stringify({ masterKey: masterKey.toString('hex'), devices: [] }));

  const testFile = path.join(sharedDir, 'test.txt');
  const originalText = 'hello cloud ' + Date.now();
  fs.writeFileSync(testFile, originalText);

  try {
    console.log(`Uploading to ${storage.getProvider()}...`);
    const entry = await storage.uploadFileToCloud(dataDir, masterKey, 'test.txt', testFile);
    console.log('Upload result:', entry ? 'ok' : 'failed');

    if (entry) {
      const redirect = await storage.getCloudRedirectInfo(dataDir, 'test.txt', testFile);
      console.log('Presigned URL generated:', redirect ? 'ok' : 'failed');

      if (redirect) {
        const response = await fetch(redirect.url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const encryptedPath = path.join(tmpDir, 'downloaded.enc');
        const decryptedPath = path.join(tmpDir, 'downloaded.txt');
        fs.writeFileSync(encryptedPath, Buffer.from(await response.arrayBuffer()));

        const { createReadStream } = require('fs');
        const { Readable } = require('stream');
        const { pipeline } = require('stream/promises');
        const { createDecipheriv } = require('crypto');

        const encrypted = fs.readFileSync(encryptedPath);
        if (encrypted.length < 16) throw new Error('Encrypted payload too short');
        if (encrypted[0] !== 0x53 || encrypted[1] !== 0x59 || encrypted[2] !== 0x4E || encrypted[3] !== 0x43) {
          throw new Error('Invalid chunked AEAD magic');
        }

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
          const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
          decipher.setAuthTag(tag);
          decryptedChunks.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
        }
        const decrypted = Buffer.concat(decryptedChunks);
        if (decrypted.toString('utf8') !== originalText) {
          throw new Error('Decrypted content mismatch');
        }
        console.log('Download + decrypt roundtrip: ok');
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
