#!/usr/bin/env node
const qiniu = require('qiniu');

function formatBytes(bytes) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

async function main() {
  const accessKey = process.env.QINIU_ACCESS_KEY;
  const secretKey = process.env.QINIU_SECRET_KEY;
  const bucket = process.env.QINIU_BUCKET;

  if (!accessKey || !secretKey || !bucket) {
    console.error('Missing Qiniu credentials. Set QINIU_ACCESS_KEY, QINIU_SECRET_KEY, QINIU_BUCKET');
    process.exit(1);
  }

  const mac = new qiniu.auth.digest.Mac(accessKey, secretKey);
  const config = new qiniu.conf.Config();
  config.zone = qiniu.zone.Zone_z0;
  const bucketManager = new qiniu.rs.BucketManager(mac, config);

  console.log('=== Qiniu Bucket Objects ===\n');

  let marker = null;
  let totalCount = 0;
  let totalSize = 0;

  do {
    const result = await new Promise((resolve, reject) => {
      bucketManager.listPrefix(bucket, { limit: 1000, marker }, (err, respBody, respInfo) => {
        if (err) reject(err);
        else resolve(respBody);
      });
    });

    if (result.items) {
      for (const item of result.items) {
        console.log(`${item.key} - ${formatBytes(item.fsize)} - ${new Date(item.putTime / 10000).toISOString()}`);
        totalCount++;
        totalSize += item.fsize;
      }
    }

    marker = result.marker || null;
  } while (marker);

  console.log(`\nTotal objects: ${totalCount}`);
  console.log(`Total size: ${formatBytes(totalSize)}`);

  console.log('\n=== Free Tier Limits ===');
  console.log('Standard Storage: 10 GB/month');
  console.log('Usage: ' + (totalSize > 0 ? `${formatBytes(totalSize)} / 10 GB (${(totalSize / 10 / 1024 / 1024 / 1024 * 100).toFixed(2)}%)` : '0 B / 10 GB (0%)'));
}

main().catch((err) => {
  console.error('Failed:', err.message);
  process.exit(1);
});
