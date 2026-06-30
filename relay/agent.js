require('dotenv').config({ path: process.env.RELAY_AGENT_ENV || '.relay-agent.env', quiet: true });

const { Readable } = require('stream');

const RELAY_URL = (process.env.RELAY_URL || '').replace(/\/+$/, '');
const ORIGIN_URL = (process.env.ORIGIN_URL || 'http://127.0.0.1:21891').replace(/\/+$/, '');
const RELAY_KEY = process.env.RELAY_KEY || '';
const WORKERS = Math.max(1, Number.parseInt(process.env.RELAY_WORKERS || '2', 10) || 2);
const IDLE_DELAY_MS = Number.parseInt(process.env.RELAY_IDLE_DELAY_MS || '500', 10);
const ERROR_DELAY_MS = Number.parseInt(process.env.RELAY_ERROR_DELAY_MS || '3000', 10);

if (!RELAY_URL) {
  console.error('RELAY_URL 未设置，例如 https://relay.example.com:8443');
  process.exit(1);
}

if (!RELAY_KEY || RELAY_KEY.length < 16) {
  console.error('RELAY_KEY 未设置或过短，relay agent 拒绝启动。');
  process.exit(1);
}

const relayHeaders = {
  authorization: `Bearer ${RELAY_KEY}`,
};

const hopByHopHeaders = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function logEvent(event, fields = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    service: 'cloudsysncd-relay-agent',
    event,
    ...fields,
  }));
}

function sanitizeHeaders(headers) {
  const output = {};
  for (const [name, value] of Object.entries(headers || {})) {
    const lower = name.toLowerCase();
    if (hopByHopHeaders.has(lower)) continue;
    if (lower === 'content-length') continue;
    output[lower] = value;
  }
  return output;
}

async function sendSyntheticResponse(jobId, status, text) {
  await fetch(`${RELAY_URL}/__relay/respond/${jobId}`, {
    method: 'POST',
    headers: {
      ...relayHeaders,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      status,
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
      },
    }),
  });

  await fetch(`${RELAY_URL}/__relay/body/${jobId}`, {
    method: 'POST',
    headers: relayHeaders,
    body: Buffer.from(text),
  });
}

async function postOriginResponse(job, originRes) {
  const responseHeaders = {};
  originRes.headers.forEach((value, name) => {
    responseHeaders[name] = value;
  });

  const metadataRes = await fetch(`${RELAY_URL}/__relay/respond/${job.id}`, {
    method: 'POST',
    headers: {
      ...relayHeaders,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      status: originRes.status,
      headers: responseHeaders,
    }),
  });

  if (!metadataRes.ok) {
    throw new Error(`relay metadata rejected: HTTP ${metadataRes.status}`);
  }

  const bodyStream = originRes.body ? Readable.fromWeb(originRes.body) : Readable.from([]);
  const bodyRes = await fetch(`${RELAY_URL}/__relay/body/${job.id}`, {
    method: 'POST',
    headers: relayHeaders,
    body: bodyStream,
    duplex: 'half',
  });

  if (!bodyRes.ok) {
    throw new Error(`relay body rejected: HTTP ${bodyRes.status}`);
  }
}

async function handleJob(job, workerId) {
  const url = `${ORIGIN_URL}${job.url}`;
  const body = job.bodyBase64 ? Buffer.from(job.bodyBase64, 'base64') : undefined;
  const hasRequestBody = body && body.length > 0 && !['GET', 'HEAD'].includes(job.method);

  logEvent('job_start', {
    workerId,
    id: job.id,
    method: job.method,
    url: job.url,
    bodyBytes: hasRequestBody ? body.length : 0,
  });

  try {
    const originRes = await fetch(url, {
      method: job.method,
      headers: sanitizeHeaders(job.headers),
      body: hasRequestBody ? body : undefined,
    });
    await postOriginResponse(job, originRes);
    logEvent('job_complete', { workerId, id: job.id, status: originRes.status });
  } catch (err) {
    logEvent('job_error', { workerId, id: job.id, error: err.message });
    try {
      await sendSyntheticResponse(job.id, 502, `Relay origin error: ${err.message}\n`);
    } catch (sendErr) {
      logEvent('synthetic_response_error', { workerId, id: job.id, error: sendErr.message });
    }
  }
}

async function poll(workerId) {
  while (true) {
    try {
      const res = await fetch(`${RELAY_URL}/__relay/next`, {
        headers: relayHeaders,
      });

      if (res.status === 204) {
        await sleep(IDLE_DELAY_MS);
        continue;
      }

      if (!res.ok) {
        throw new Error(`relay next failed: HTTP ${res.status}`);
      }

      const job = await res.json();
      await handleJob(job, workerId);
    } catch (err) {
      logEvent('poll_error', { workerId, error: err.message });
      await sleep(ERROR_DELAY_MS);
    }
  }
}

logEvent('started', {
  relayUrl: RELAY_URL,
  originUrl: ORIGIN_URL,
  workers: WORKERS,
});

for (let i = 0; i < WORKERS; i += 1) {
  poll(i + 1);
}
