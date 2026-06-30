require('dotenv').config({ path: process.env.RELAY_ENV || '.relay-server.env', quiet: true });

const crypto = require('crypto');
const express = require('express');
const { pipeline } = require('stream/promises');

const app = express();

const RELAY_PORT = Number.parseInt(process.env.RELAY_PORT || '21890', 10);
const RELAY_KEY = process.env.RELAY_KEY || '';
const RELAY_ACCESS_KEY = process.env.RELAY_ACCESS_KEY || '';
const RELAY_ACCESS_FORM_ENABLED = parseBooleanEnv(process.env.RELAY_ACCESS_FORM_ENABLED, false);
const RELAY_ACCESS_COOKIE = process.env.RELAY_ACCESS_COOKIE || 'syncd_relay_access';
const RELAY_ACCESS_COOKIE_MAX_AGE_SECONDS = Number.parseInt(
  process.env.RELAY_ACCESS_COOKIE_MAX_AGE_SECONDS || String(30 * 24 * 60 * 60),
  10
);
const LONG_POLL_MS = Number.parseInt(process.env.RELAY_LONG_POLL_MS || '30000', 10);
const REQUEST_TIMEOUT_MS = Number.parseInt(process.env.RELAY_REQUEST_TIMEOUT_MS || String(10 * 60 * 1000), 10);
const MAX_REQUEST_BYTES = process.env.RELAY_MAX_REQUEST_BYTES || '1mb';
const MAX_PENDING_JOBS = Number.parseInt(process.env.RELAY_MAX_PENDING_JOBS || '8', 10);
const ACCESS_LOGIN_LIMIT = Number.parseInt(process.env.RELAY_ACCESS_LOGIN_LIMIT || '10', 10);
const ACCESS_LOGIN_WINDOW_MS = Number.parseInt(process.env.RELAY_ACCESS_LOGIN_WINDOW_MS || String(10 * 60 * 1000), 10);
const ACCESS_LOGIN_BLOCK_MS = Number.parseInt(process.env.RELAY_ACCESS_LOGIN_BLOCK_MS || String(10 * 60 * 1000), 10);
const MAX_JOB_BODY_BYTES = Number.parseInt(process.env.RELAY_MAX_JOB_BODY_BYTES || String(1024 * 1024), 10);
const MAX_JOB_HEADER_BYTES = Number.parseInt(process.env.RELAY_MAX_JOB_HEADER_BYTES || String(32 * 1024), 10);
const ACCESS_AUTH_WINDOW_MS = Number.parseInt(process.env.RELAY_ACCESS_AUTH_WINDOW_MS || String(5 * 60 * 1000), 10);
const ACCESS_NONCE_TTL_MS = Number.parseInt(process.env.RELAY_ACCESS_NONCE_TTL_MS || String(10 * 60 * 1000), 10);
const MAX_ACCESS_NONCES = Number.parseInt(process.env.RELAY_MAX_ACCESS_NONCES || '4096', 10);
const RELAY_ACCEPT_LEGACY_ACCESS_KEY = parseBooleanEnv(process.env.RELAY_ACCEPT_LEGACY_ACCESS_KEY, false);
const RELAY_REQUIRE_HTTPS = parseBooleanEnv(process.env.RELAY_REQUIRE_HTTPS, false);
const RELAY_ACCESS_COOKIE_SECURE = parseCookieSecureMode(process.env.RELAY_ACCESS_COOKIE_SECURE || 'auto');
const RELAY_CORS_ORIGINS = parseOriginList(process.env.RELAY_CORS_ORIGINS || '*');

if (!RELAY_KEY || RELAY_KEY.length < 16) {
  console.error('RELAY_KEY 未设置或过短，relay server 拒绝启动。');
  process.exit(1);
}

const pendingJobs = new Map();
const jobQueue = [];
const waitingAgents = [];
const accessLoginState = new Map();
const seenAccessNonces = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [ip, state] of accessLoginState.entries()) {
    if (state.blockedUntil && state.blockedUntil > now) continue;
    if (now - state.windowStart > ACCESS_LOGIN_WINDOW_MS) {
      accessLoginState.delete(ip);
    }
  }
}, Math.max(ACCESS_LOGIN_WINDOW_MS, ACCESS_LOGIN_BLOCK_MS));

setInterval(() => {
  pruneAccessNonces();
}, Math.max(ACCESS_NONCE_TTL_MS, 60 * 1000));

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

function timingSafeEqualString(a, b) {
  const aBuf = Buffer.from(a || '');
  const bBuf = Buffer.from(b || '');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function hmacHex(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function parseBooleanEnv(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function parseCookieSecureMode(value) {
  const normalized = String(value || 'auto').trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on') return 'true';
  if (normalized === 'false' || normalized === '0' || normalized === 'no' || normalized === 'off') return 'false';
  return 'auto';
}

function parseOriginList(value) {
  const entries = String(value || '')
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  return entries.length > 0 ? entries : ['*'];
}

function isHttpsRequest(req) {
  const forwardedProto = String(req.get('x-forwarded-proto') || '').split(',')[0].trim().toLowerCase();
  if (forwardedProto) return forwardedProto === 'https';
  return Boolean(req.secure || (req.socket && req.socket.encrypted));
}

function shouldUseSecureCookie(req) {
  if (RELAY_ACCESS_COOKIE_SECURE === 'true') return true;
  if (RELAY_ACCESS_COOKIE_SECURE === 'false') return false;
  return isHttpsRequest(req);
}

function getCorsOrigin(req) {
  const origin = String(req.get('origin') || '').trim();
  if (!origin) return '';
  if (RELAY_CORS_ORIGINS.includes('*')) return '*';
  return RELAY_CORS_ORIGINS.includes(origin) ? origin : '';
}

function applyCorsHeaders(req, res) {
  const allowedOrigin = getCorsOrigin(req);
  if (!allowedOrigin) return;
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', [
    'Content-Type',
    'X-Relay-Access-Key',
    'X-Relay-Access-Key-Id',
    'X-Relay-Access-Timestamp',
    'X-Relay-Access-Nonce',
    'X-Relay-Access-Signature',
    'X-Device-Id',
    'X-Auth-Timestamp',
    'X-Auth-Nonce',
    'X-Auth-Signature',
  ].join(', '));
  res.setHeader('Access-Control-Expose-Headers', [
    'X-Encrypted-IV',
    'X-Encrypted-Tag-Length',
    'X-Encryption-Format',
    'X-File-Name',
    'X-File-Size',
    'X-Archive-Count',
    'X-Archive-Total-Size',
    'X-Batch-Count',
    'X-Batch-Total-Size',
    'X-Batch-Snapshot-At',
    'X-Storage-Backend',
  ].join(', '));
  res.setHeader('Access-Control-Max-Age', '600');
}

function requireRelayAuth(req, res, next) {
  const expected = `Bearer ${RELAY_KEY}`;
  const actual = req.get('authorization') || '';
  if (!timingSafeEqualString(actual, expected)) {
    return res.status(401).json({ error: 'Unauthorized relay agent' });
  }
  return next();
}

function getRemoteIdentity(req) {
  const forwardedFor = String(req.get('x-forwarded-for') || '').split(',')[0].trim();
  if (forwardedFor) return forwardedFor;
  const realIp = String(req.get('x-real-ip') || '').trim();
  if (realIp) return realIp;
  return req.socket.remoteAddress || req.ip || 'unknown';
}

function rateLimitLogin(req, res, next) {
  const now = Date.now();
  const ip = getRemoteIdentity(req);
  const state = accessLoginState.get(ip) || { attempts: 0, windowStart: now, blockedUntil: 0 };

  if (state.blockedUntil > now) {
    return res.status(429).send('Too many attempts');
  }

  if (now - state.windowStart > ACCESS_LOGIN_WINDOW_MS) {
    state.attempts = 0;
    state.windowStart = now;
  }

  req.__relayLoginState = state;
  req.__relayLoginIp = ip;
  next();
}

function parseCookies(cookieHeader) {
  const cookies = {};
  for (const part of String(cookieHeader || '').split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name) continue;
    cookies[name] = decodeURIComponent(value);
  }
  return cookies;
}

function stripRelayCookie(cookieHeader) {
  const kept = [];
  for (const part of String(cookieHeader || '').split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    if (!name || name === RELAY_ACCESS_COOKIE) continue;
    kept.push(part.trim());
  }
  return kept.join('; ');
}

function relayCookieToken() {
  if (!RELAY_ACCESS_KEY) return '';
  return crypto
    .createHmac('sha256', RELAY_ACCESS_KEY)
    .update('cloudsysncd-relay-cookie-v1')
    .digest('hex');
}

function isLegacyRelayAccessKey(candidate) {
  return Boolean(RELAY_ACCESS_KEY) && timingSafeEqualString(candidate || '', RELAY_ACCESS_KEY);
}

function pruneAccessNonces(now = Date.now()) {
  for (const [nonce, seenAt] of seenAccessNonces.entries()) {
    if (now - seenAt > ACCESS_NONCE_TTL_MS) {
      seenAccessNonces.delete(nonce);
    }
  }
  if (seenAccessNonces.size <= MAX_ACCESS_NONCES) return;
  const overflow = seenAccessNonces.size - MAX_ACCESS_NONCES;
  let removed = 0;
  for (const nonce of seenAccessNonces.keys()) {
    seenAccessNonces.delete(nonce);
    removed++;
    if (removed >= overflow) break;
  }
}

function verifyRelayAccessSignature(req) {
  if (!RELAY_ACCESS_KEY) return { ok: true };

  const timestamp = req.get('x-relay-access-timestamp') || '';
  const nonce = req.get('x-relay-access-nonce') || '';
  const signature = req.get('x-relay-access-signature') || '';
  if (!timestamp || !nonce || !signature) {
    return { ok: false, status: 401, message: 'Missing relay access signature' };
  }

  const timestampMs = Number(timestamp);
  const now = Date.now();
  if (!Number.isFinite(timestampMs) || Math.abs(now - timestampMs) > ACCESS_AUTH_WINDOW_MS) {
    return { ok: false, status: 401, message: 'Relay access timestamp expired' };
  }

  pruneAccessNonces(now);
  if (seenAccessNonces.has(nonce)) {
    return { ok: false, status: 409, message: 'Relay access replay detected' };
  }

  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const bodyHash = sha256Hex(body);
  const message = [req.method.toUpperCase(), req.originalUrl, String(timestamp), String(nonce), bodyHash].join('\n');
  const expected = hmacHex(RELAY_ACCESS_KEY, message);
  if (!timingSafeEqualString(signature, expected)) {
    return { ok: false, status: 401, message: 'Invalid relay access signature' };
  }

  seenAccessNonces.set(nonce, now);
  return { ok: true };
}

function getPublicAccessFailure(req) {
  if (!RELAY_ACCESS_KEY) return null;
  const signatureResult = verifyRelayAccessSignature(req);
  if (signatureResult.ok) return null;

  if (RELAY_ACCEPT_LEGACY_ACCESS_KEY && isLegacyRelayAccessKey(req.get('x-relay-access-key') || '')) return null;

  const cookieKey = parseCookies(req.get('cookie'))[RELAY_ACCESS_COOKIE] || '';
  if (timingSafeEqualString(cookieKey, relayCookieToken())) return null;

  return signatureResult;
}

function setRelayAccessCookie(req, res) {
  const cookieValue = encodeURIComponent(relayCookieToken());
  const maxAge = Math.max(60, RELAY_ACCESS_COOKIE_MAX_AGE_SECONDS);
  const cookieParts = [
    `${RELAY_ACCESS_COOKIE}=${cookieValue}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (shouldUseSecureCookie(req)) cookieParts.push('Secure');
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function clearRelayAccessCookie(req, res) {
  const cookieParts = [
    `${RELAY_ACCESS_COOKIE}=`,
    'Max-Age=0',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (shouldUseSecureCookie(req)) cookieParts.push('Secure');
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function sendAccessForm(res, status = 200, message = '') {
  res.status(status).type('html').send(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>syncd relay access</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #111; }
    main { max-width: 420px; margin: 10vh auto; }
    label, input, button { display: block; width: 100%; box-sizing: border-box; }
    label { font-size: 14px; margin-bottom: 8px; }
    input { font: inherit; padding: 10px 12px; border: 1px solid #bbb; border-radius: 6px; }
    button { margin-top: 12px; padding: 10px 12px; border: 0; border-radius: 6px; background: #111; color: white; font: inherit; }
    p { color: #b00020; min-height: 1.4em; }
  </style>
</head>
<body>
  <main>
    <h1>syncd relay access</h1>
    <p>${message}</p>
    <form method="post" action="/__relay/access">
      <label for="relay_key">Relay access key</label>
      <input id="relay_key" name="relay_key" type="password" autocomplete="current-password" autofocus>
      <button type="submit">进入</button>
    </form>
  </main>
</body>
</html>`);
}

function sanitizeHeaders(headers, { keepContentLength = false } = {}) {
  const output = {};
  for (const [name, value] of Object.entries(headers || {})) {
    const lower = name.toLowerCase();
    if (hopByHopHeaders.has(lower)) continue;
    if (!keepContentLength && lower === 'content-length') continue;
    if (lower === 'authorization' && value === `Bearer ${RELAY_KEY}`) continue;
    if (lower === 'x-relay-access-key') continue;
    if (lower.startsWith('x-relay-access-')) continue;
    if (lower === 'cookie') {
      const stripped = stripRelayCookie(Array.isArray(value) ? value.join('; ') : String(value));
      if (stripped) output[lower] = stripped;
      continue;
    }
    output[lower] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return output;
}

function writeJsonJob(res, job) {
  res.json({
    id: job.id,
    method: job.method,
    url: job.url,
    headers: job.headers,
    bodyBase64: job.body.toString('base64'),
  });
}

function deliverJob(job) {
  while (waitingAgents.length > 0) {
    const waiter = waitingAgents.shift();
    if (waiter.done) continue;
    waiter.done = true;
    clearTimeout(waiter.timer);
    writeJsonJob(waiter.res, job);
    return true;
  }
  return false;
}

function cleanupJob(id, err) {
  const job = pendingJobs.get(id);
  if (!job) return;
  pendingJobs.delete(id);
  clearTimeout(job.timer);
  const queueIndex = jobQueue.findIndex((queued) => queued.id === id);
  if (queueIndex >= 0) jobQueue.splice(queueIndex, 1);
  if (!job.clientRes.headersSent && !job.clientRes.destroyed) {
    const status = err && err.statusCode ? err.statusCode : 504;
    job.clientRes.status(status).json({ error: err ? err.message : 'Relay request expired' });
  } else if (!job.clientRes.writableEnded && !job.clientRes.destroyed) {
    job.clientRes.destroy(err || new Error('Relay request expired'));
  }
}

function logEvent(event, fields = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    service: 'cloudsysncd-relay',
    event,
    ...fields,
  }));
}

function maybeRequireHttps(req, res, next) {
  if (RELAY_REQUIRE_HTTPS && !isHttpsRequest(req)) {
    return res.status(403).json({ error: 'HTTPS required' });
  }
  return next();
}

app.disable('x-powered-by');

app.use((req, res, next) => {
  applyCorsHeaders(req, res);
  if (req.method === 'OPTIONS' && req.get('access-control-request-method')) {
    return res.status(204).end();
  }
  return next();
});

app.get('/__relay/healthz', (req, res) => {
  res.json({
    ok: true,
    service: 'cloudsysncd-relay',
    queued: jobQueue.length,
    pending: pendingJobs.size,
    waitingAgents: waitingAgents.filter((waiter) => !waiter.done).length,
    uptimeSeconds: Math.round(process.uptime()),
  });
});

app.get('/__relay/access', maybeRequireHttps, (req, res) => {
  if (!RELAY_ACCESS_KEY || !RELAY_ACCESS_FORM_ENABLED) {
    return res.status(404).json({ error: 'Relay public access key is not enabled' });
  }
  return sendAccessForm(res);
});

app.post('/__relay/access', maybeRequireHttps, rateLimitLogin, express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
  if (!RELAY_ACCESS_KEY || !RELAY_ACCESS_FORM_ENABLED) {
    return res.status(404).json({ error: 'Relay public access key is not enabled' });
  }
  const state = req.__relayLoginState;
  const ip = req.__relayLoginIp;
  if (!isLegacyRelayAccessKey(req.body && req.body.relay_key)) {
    if (state) {
      state.attempts += 1;
      if (state.attempts >= ACCESS_LOGIN_LIMIT) {
        state.blockedUntil = Date.now() + ACCESS_LOGIN_BLOCK_MS;
      }
      accessLoginState.set(ip, state);
    }
    return sendAccessForm(res, 401, '访问 key 不正确');
  }
  accessLoginState.delete(ip);
  setRelayAccessCookie(req, res);
  return res.redirect(302, '/');
});

app.post('/__relay/access/logout', maybeRequireHttps, (req, res) => {
  clearRelayAccessCookie(req, res);
  res.redirect(302, '/__relay/access');
});

app.get('/__relay/next', requireRelayAuth, (req, res) => {
  const queued = jobQueue.shift();
  if (queued) {
    writeJsonJob(res, queued);
    return;
  }

  const waiter = { res, done: false, timer: null };
  waiter.timer = setTimeout(() => {
    if (waiter.done) return;
    waiter.done = true;
    res.status(204).end();
  }, LONG_POLL_MS);

  res.on('close', () => {
    waiter.done = true;
    clearTimeout(waiter.timer);
  });

  waitingAgents.push(waiter);
});

app.post('/__relay/respond/:id', requireRelayAuth, express.json({ limit: '1mb' }), (req, res) => {
  const job = pendingJobs.get(req.params.id);
  if (!job) {
    return res.status(404).json({ error: 'Relay job not found' });
  }

  const status = Number.parseInt(req.body && req.body.status, 10) || 502;
  const responseHeaders = sanitizeHeaders(req.body && req.body.headers, { keepContentLength: false });

  if (!job.clientRes.headersSent) {
    job.clientRes.status(status);
    for (const [name, value] of Object.entries(responseHeaders)) {
      job.clientRes.setHeader(name, value);
    }
  }

  return res.json({ ok: true });
});

app.post('/__relay/body/:id', requireRelayAuth, async (req, res) => {
  const job = pendingJobs.get(req.params.id);
  if (!job) {
    req.resume();
    return res.status(404).json({ error: 'Relay job not found' });
  }

  try {
    await pipeline(req, job.clientRes);
    pendingJobs.delete(job.id);
    clearTimeout(job.timer);
    logEvent('request_complete', { id: job.id, method: job.method, url: job.url });
    return res.json({ ok: true });
  } catch (err) {
    pendingJobs.delete(job.id);
    clearTimeout(job.timer);
    if (!job.clientRes.destroyed) job.clientRes.destroy(err);
    logEvent('request_body_error', { id: job.id, error: err.message });
    return res.status(500).json({ error: 'Relay body stream failed' });
  }
});

app.post('/__relay/discard', requireRelayAuth, async (req, res) => {
  let bytes = 0;
  const startedAt = Date.now();
  let tooLarge = false;

  try {
    for await (const chunk of req) {
      bytes += chunk.length;
      if (bytes > MAX_JOB_BODY_BYTES) {
        tooLarge = true;
      }
    }
    if (tooLarge) {
      return res.status(413).json({ error: 'Relay request body too large' });
    }
    const elapsedMs = Math.max(1, Date.now() - startedAt);
    return res.json({
      ok: true,
      bytes,
      elapsedMs,
      bytesPerSecond: Math.round((bytes * 1000) / elapsedMs),
    });
  } catch (err) {
    logEvent('discard_error', { error: err.message });
    return res.status(500).json({ error: 'Discard stream failed' });
  }
});

app.all(/^\/__relay(?:\/.*)?$/, (req, res) => {
  res.status(404).json({ error: 'Relay endpoint not found' });
});

app.use(express.raw({
  type: () => true,
  limit: MAX_REQUEST_BYTES,
  verify: (req, res, buf) => {
    if (buf.length > MAX_JOB_BODY_BYTES) {
      throw new Error('Relay request body too large');
    }
  },
}));

app.all(/.*/, (req, res) => {
  const accessFailure = getPublicAccessFailure(req);
  if (accessFailure) {
    return res.status(accessFailure.status || 401).json({ error: accessFailure.message || 'Missing or invalid relay access key' });
  }

  if (req.path.startsWith('/api/local/')) {
    return res.status(403).json({ error: 'Local admin API is not exposed through relay' });
  }

  if (pendingJobs.size >= MAX_PENDING_JOBS) {
    return res.status(503).json({ error: 'Relay is busy' });
  }

  const id = crypto.randomUUID();
  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const headerSize = Buffer.byteLength(JSON.stringify(req.headers || {}), 'utf8');
  if (body.length > MAX_JOB_BODY_BYTES) {
    return res.status(413).json({ error: 'Relay request body too large' });
  }
  if (headerSize > MAX_JOB_HEADER_BYTES) {
    return res.status(431).json({ error: 'Relay request headers too large' });
  }
  const job = {
    id,
    method: req.method,
    url: req.originalUrl,
    headers: sanitizeHeaders(req.headers, { keepContentLength: true }),
    body,
    clientRes: res,
    timer: null,
  };

  job.timer = setTimeout(() => {
    cleanupJob(id, new Error('Relay request timed out'));
  }, REQUEST_TIMEOUT_MS);

  res.on('close', () => {
    if (res.writableEnded) return;
    cleanupJob(id, new Error('Client disconnected'));
  });

  pendingJobs.set(id, job);

  if (!deliverJob(job)) {
    jobQueue.push(job);
  }

  logEvent('request_queued', {
    id,
    method: job.method,
    url: job.url,
    bodyBytes: body.length,
    queued: jobQueue.length,
    pending: pendingJobs.size,
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Relay request body too large' });
  }
  if (err && err.message === 'Relay request body too large') {
    return res.status(413).json({ error: 'Relay request body too large' });
  }
  console.error('Relay error:', err);
  return res.status(500).json({ error: 'Relay server error' });
});

app.listen(RELAY_PORT, '127.0.0.1', () => {
  logEvent('started', {
    port: RELAY_PORT,
    maxRequestBytes: MAX_REQUEST_BYTES,
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
    publicAccessKeyRequired: Boolean(RELAY_ACCESS_KEY),
    requireHttps: RELAY_REQUIRE_HTTPS,
    accessCookieSecure: RELAY_ACCESS_COOKIE_SECURE,
  });
});
