const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');
const { createDecipheriv } = require('crypto');

if (process.env.HYBRID_SMOKE_LOAD_ENV === 'true') {
  require('dotenv').config();
}

const REMOTE_MODE = process.env.HYBRID_SMOKE_REMOTE === 'true';

process.env.STORAGE_PROVIDER = REMOTE_MODE ? 'hybrid' : 'local';
process.env.STORAGE_DOWNLOAD_MODE = process.env.STORAGE_DOWNLOAD_MODE || 'proxy';
process.env.STORAGE_FALLBACK_BYTES = process.env.STORAGE_FALLBACK_BYTES || '0';
process.env.STORAGE_REMOTE_THRESHOLD_BYTES = process.env.STORAGE_REMOTE_THRESHOLD_BYTES || String(128 * 1024);
process.env.STORAGE_AEAD_CHUNK_BYTES = process.env.STORAGE_AEAD_CHUNK_BYTES || String(256 * 1024);
process.env.STORAGE_REMOTE_PART_BYTES = process.env.STORAGE_REMOTE_PART_BYTES || String(5 * 1024 * 1024);
process.env.STORAGE_LOCAL_MAX_BYTES = process.env.STORAGE_LOCAL_MAX_BYTES || String(10 * 1024 * 1024 * 1024);
process.env.STORAGE_REQUEST_TIMEOUT_MS = process.env.STORAGE_REQUEST_TIMEOUT_MS || String(120 * 1000);

const storage = require('../lib/cloud-storage');

async function decryptChunkedAeadFile(key, encryptedPath, outputPath) {
  const HEADER_LEN = 16;
  const IV_LEN = 12;
  const LENGTH_LEN = 4;
  const TAG_LEN = 16;
  const encrypted = fs.readFileSync(encryptedPath);

  if (encrypted.length < HEADER_LEN) throw new Error('Chunked AEAD response too short');
  if (encrypted.subarray(0, 4).toString('ascii') !== 'SYNC') throw new Error('Invalid chunked AEAD magic');
  if (encrypted[4] !== 1) throw new Error('Unsupported chunked AEAD version');
  const chunkSize = encrypted.readUInt32BE(5);

  let offset = HEADER_LEN;
  const chunks = [];
  let chunkCount = 0;
  let finalized = false;
  while (offset < encrypted.length) {
    if (offset + IV_LEN + LENGTH_LEN > encrypted.length) throw new Error('Truncated chunk frame header');
    const iv = encrypted.subarray(offset, offset + IV_LEN);
    offset += IV_LEN;
    const len = encrypted.readUInt32BE(offset);
    offset += LENGTH_LEN;

    if (len === 0xffffffff) {
      if (offset + 12 + TAG_LEN > encrypted.length) throw new Error('Truncated final chunk frame');
      const ciphertext = encrypted.subarray(offset, offset + 12);
      offset += 12;
      const tag = encrypted.subarray(offset, offset + TAG_LEN);
      offset += TAG_LEN;

      const decipher = createDecipheriv('aes-256-gcm', key, iv);
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

    if (offset + len + TAG_LEN > encrypted.length) throw new Error('Truncated chunk frame body');
    const ciphertext = encrypted.subarray(offset, offset + len);
    offset += len;
    const tag = encrypted.subarray(offset, offset + TAG_LEN);
    offset += TAG_LEN;

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    chunks.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    chunkCount++;
  }
  if (!finalized) throw new Error('Missing chunked AEAD final frame');

  fs.writeFileSync(outputPath, Buffer.concat(chunks));
}

async function roundtrip(dataDir, masterKey, relPath, fullPath, expectedBackend) {
  const entry = await storage.uploadFileToCloud(dataDir, masterKey, relPath, fullPath);
  if (!entry) throw new Error(`Upload failed for ${relPath}`);
  if (entry.backend !== expectedBackend) {
    throw new Error(`Expected ${relPath} backend ${expectedBackend}, got ${entry.backend}`);
  }

  const info = await storage.getCloudRedirectInfo(dataDir, relPath, fullPath);
  if (!info || !info.proxy) throw new Error(`Proxy info missing for ${relPath}`);
  if (info.backend !== expectedBackend) {
    throw new Error(`Expected proxy backend ${expectedBackend}, got ${info.backend}`);
  }

  const encryptedPath = path.join(path.dirname(fullPath), `${relPath}.enc`);
  const decryptedPath = path.join(path.dirname(fullPath), `${relPath}.out`);
  const readStream = await storage.createCloudReadStream(dataDir, info);
  await pipeline(readStream, fs.createWriteStream(encryptedPath));
  await decryptChunkedAeadFile(masterKey, encryptedPath, decryptedPath);

  const original = fs.readFileSync(fullPath);
  const decrypted = fs.readFileSync(decryptedPath);
  if (!crypto.timingSafeEqual(crypto.createHash('sha256').update(original).digest(), crypto.createHash('sha256').update(decrypted).digest())) {
    throw new Error(`Roundtrip mismatch for ${relPath}`);
  }
  return entry;
}

async function main() {
  if (!storage.isStorageEnabled()) {
    throw new Error('Hybrid storage is not enabled');
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syncd-hybrid-smoke-'));
  const dataDir = path.join(tmpDir, 'data');
  const sharedDir = path.join(tmpDir, 'shared');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(sharedDir, { recursive: true });

  const masterKey = crypto.randomBytes(32);
  const smallPath = path.join(sharedDir, 'small.txt');
  const largePath = path.join(sharedDir, 'large.bin');
  fs.writeFileSync(smallPath, Buffer.from('small hybrid smoke ' + Date.now()));
    fs.writeFileSync(largePath, crypto.randomBytes(256 * 1024));

  try {
    const small = await roundtrip(dataDir, masterKey, 'small.txt', smallPath, 'local');
    console.log(`small_backend=${small.backend}`);
    const largeExpectedBackend = REMOTE_MODE ? 'remote' : 'local';
    const large = await roundtrip(dataDir, masterKey, 'large.bin', largePath, largeExpectedBackend);
    console.log(`large_backend=${large.backend}`);

    await storage.deleteCloudObjectForPath(dataDir, 'small.txt');
    await storage.deleteCloudObjectForPath(dataDir, 'large.bin');
    console.log('cleanup=ok');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
