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

        const chunkSize = encrypted.readUInt32BE(5);
        let offset = 16;
        const decryptedChunks = [];
        let chunkCount = 0;
        let finalized = false;
        while (offset < encrypted.length) {
          if (offset + 16 > encrypted.length) throw new Error('Truncated chunk frame header');
          const iv = encrypted.subarray(offset, offset + 12);
          offset += 12;
          const len = encrypted.readUInt32BE(offset);
          offset += 4;

          if (len === 0xffffffff) {
            if (offset + 12 + 16 > encrypted.length) throw new Error('Truncated final chunk frame');
            const ciphertext = encrypted.subarray(offset, offset + 12);
            offset += 12;
            const tag = encrypted.subarray(offset, offset + 16);
            offset += 16;
            const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
            decipher.setAAD(Buffer.from('SYNC-FINAL-v1'));
            decipher.setAuthTag(tag);
            const finalPlaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            const expectedChunks = Number(finalPlaintext.readBigUInt64BE(0));
            const expectedChunkSize = finalPlaintext.readUInt32BE(8);
            if (expectedChunks !== chunkCount || expectedChunkSize !== chunkSize) {
              throw new Error('Invalid chunked AEAD final frame');
            }
            finalized = true;
            if (offset !== encrypted.length) throw new Error('Trailing data after final frame');
            break;
          }

          if (offset + len + 16 > encrypted.length) throw new Error('Truncated chunk frame body');
          const ciphertext = encrypted.subarray(offset, offset + len);
          offset += len;
          const tag = encrypted.subarray(offset, offset + 16);
          offset += 16;
          const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
          decipher.setAuthTag(tag);
          decryptedChunks.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
          chunkCount++;
        }
        if (!finalized) throw new Error('Missing chunked AEAD final frame');
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
