const crypto = require('crypto');
const { Readable } = require('stream');

const CHUNKED_AEAD_MAGIC = Buffer.from('SYNC');
const CHUNKED_AEAD_VERSION = 1;
const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = 16;
const FINAL_FRAME_TYPE = 0xffffffff;
const FINAL_AAD = Buffer.from('SYNC-FINAL-v1');

function createChunkedAeadStream(sourceStream, key, chunkSize = DEFAULT_CHUNK_SIZE) {
  const ivBase = crypto.randomBytes(IV_LENGTH);
  let chunkIndex = 0;

  async function* generator() {
    yield Buffer.concat([
      CHUNKED_AEAD_MAGIC,
      Buffer.from([CHUNKED_AEAD_VERSION]),
      Buffer.from([(chunkSize >> 24) & 0xff, (chunkSize >> 16) & 0xff, (chunkSize >> 8) & 0xff, chunkSize & 0xff]),
      Buffer.alloc(7),
    ]);

    const buffers = [];
    let buffered = 0;

    for await (const data of sourceStream) {
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
      buffers.push(chunk);
      buffered += chunk.length;

      while (buffered >= chunkSize) {
        const plaintext = Buffer.concat(buffers);
        const block = plaintext.subarray(0, chunkSize);
        const remainder = plaintext.subarray(chunkSize);
        buffers.length = 0;
        if (remainder.length > 0) buffers.push(remainder);
        buffered = remainder.length;

        const iv = deriveChunkIv(ivBase, chunkIndex);
        chunkIndex++;
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(block), cipher.final()]);
        const tag = cipher.getAuthTag();

        yield Buffer.concat([
          iv,
          Buffer.from([(ciphertext.length >> 24) & 0xff, (ciphertext.length >> 16) & 0xff, (ciphertext.length >> 8) & 0xff, ciphertext.length & 0xff]),
          ciphertext,
          tag,
        ]);
      }
    }

    if (buffered > 0) {
      const plaintext = Buffer.concat(buffers);
      const iv = deriveChunkIv(ivBase, chunkIndex);
      chunkIndex++;
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();

      yield Buffer.concat([
        iv,
        Buffer.from([(ciphertext.length >> 24) & 0xff, (ciphertext.length >> 16) & 0xff, (ciphertext.length >> 8) & 0xff, ciphertext.length & 0xff]),
        ciphertext,
        tag,
      ]);
    }

    const finalIv = deriveChunkIv(ivBase, chunkIndex);
    const finalCipher = crypto.createCipheriv('aes-256-gcm', key, finalIv);
    finalCipher.setAAD(FINAL_AAD);
    const finalPlaintext = Buffer.alloc(12);
    finalPlaintext.writeBigUInt64BE(BigInt(chunkIndex), 0);
    finalPlaintext.writeUInt32BE(chunkSize, 8);
    const finalCiphertext = Buffer.concat([finalCipher.update(finalPlaintext), finalCipher.final()]);
    const finalTag = finalCipher.getAuthTag();

    yield Buffer.concat([
      finalIv,
      Buffer.from([0xff, 0xff, 0xff, 0xff]),
      finalCiphertext,
      finalTag,
    ]);
  }

  return {
    stream: Readable.from(generator()),
    ivBaseHex: ivBase.toString('hex'),
  };
}

function deriveChunkIv(ivBase, chunkIndex) {
  const iv = Buffer.from(ivBase);
  const indexBytes = Buffer.alloc(4);
  indexBytes.writeUInt32BE(chunkIndex, 0);
  for (let i = 0; i < 4; i++) {
    iv[IV_LENGTH - 4 + i] ^= indexBytes[i];
  }
  return iv;
}

module.exports = {
  createChunkedAeadStream,
  deriveChunkIv,
  HEADER_LENGTH,
  IV_LENGTH,
  TAG_LENGTH,
  DEFAULT_CHUNK_SIZE,
  FINAL_FRAME_TYPE,
  FINAL_AAD,
};
