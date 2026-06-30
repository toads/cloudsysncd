#!/usr/bin/env node
const https = require('https');
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

function getTodayRange() {
  const now = new Date();
  const begin = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0);
  const end = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, 0, 0, 0);
  return {
    begin: begin.toISOString().replace(/[-:T]/g, '').slice(0, 14),
    end: end.toISOString().replace(/[-:T]/g, '').slice(0, 14),
  };
}

function requestWithQiniuAuth(host, path, mac) {
  return new Promise((resolve, reject) => {
    const url = `https://${host}${path}`;
    const accessToken = qiniu.util.generateAccessToken(mac, url);
    const options = {
      hostname: host,
      path,
      method: 'GET',
      headers: {
        Authorization: accessToken,
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
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
  const today = getTodayRange();

  console.log('=== Qiniu Storage Usage ===\n');
  console.log(`Bucket: ${bucket}`);
  console.log(`Date range: ${today.begin} - ${today.end}\n`);

  try {
    const spaceRes = await requestWithQiniuAuth(
      'api.qiniuapi.com',
      `/v6/space?bucket=${encodeURIComponent(bucket)}&begin=${today.begin}&end=${today.end}&g=day`,
      mac
    );

    if (spaceRes.error) {
      console.error('Space API error:', spaceRes.error);
    } else if (spaceRes.datas && spaceRes.datas.length > 0) {
      const latest = spaceRes.datas[spaceRes.datas.length - 1];
      console.log(`Storage usage: ${formatBytes(latest)}`);
    } else {
      console.log('Storage usage: no data');
    }
  } catch (err) {
    console.error('Space API error:', err.message);
  }

  try {
    const countRes = await requestWithQiniuAuth(
      'api.qiniuapi.com',
      `/v6/count?bucket=${encodeURIComponent(bucket)}&begin=${today.begin}&end=${today.end}&g=day`,
      mac
    );

    if (countRes.error) {
      console.error('Count API error:', countRes.error);
    } else if (countRes.datas && countRes.datas.length > 0) {
      const latest = countRes.datas[countRes.datas.length - 1];
      console.log(`File count: ${latest.toLocaleString()}`);
    } else {
      console.log('File count: no data');
    }
  } catch (err) {
    console.error('Count API error:', err.message);
  }

  try {
    const ioRes = await requestWithQiniuAuth(
      'api.qiniuapi.com',
      `/v6/blob_io?begin=${today.begin}&end=${today.end}&g=day&select=hits`,
      mac
    );

    if (ioRes.error) {
      console.error('Blob IO API error:', ioRes.error);
    } else if (Array.isArray(ioRes) && ioRes.length > 0) {
      const latest = ioRes[ioRes.length - 1];
      console.log(`GET requests (hits): ${latest.hits?.toLocaleString() || 0}`);
      console.log(`Traffic (flow): ${formatBytes(latest.flow || 0)}`);
    } else {
      console.log('Request stats: no data');
    }
  } catch (err) {
    console.error('Blob IO API error:', err.message);
  }

  console.log('\n=== Free Tier Limits ===');
  console.log('Standard Storage: 10 GB/month');
  console.log('CDN Origin Flow: 10 GB/month');
  console.log('PUT/DELETE requests: 100K/month');
  console.log('GET requests: 1M/month');
}

main().catch((err) => {
  console.error('Failed:', err.message);
  process.exit(1);
});
