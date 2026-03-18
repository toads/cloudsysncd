// ============ Crypto Utilities (Web Crypto API) ============

const Crypto = {
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const pubRaw = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
    return { keyPair, publicKeyHex: buf2hex(new Uint8Array(pubRaw)) };
  },

  async importPublicKey(hex) {
    return window.crypto.subtle.importKey(
      'raw',
      hex2buf(hex),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
  },

  async deriveSharedSecret(privateKey, publicKey) {
    const bits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256
    );
    return new Uint8Array(bits);
  },

  async hkdf(ikm, salt, info, length = 32) {
    const baseKey = await window.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await window.crypto.subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(salt),
      info: new TextEncoder().encode(info),
    }, baseKey, length * 8);
    return new Uint8Array(bits);
  },

  async hmac(key, data) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
    return buf2hex(new Uint8Array(signature));
  },

  async decryptBytes(keyBytes, ivBytes, ciphertextBytes, tagBytes) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combined.set(ciphertextBytes);
    combined.set(tagBytes, ciphertextBytes.length);
    return new Uint8Array(await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, combined));
  },

  async decrypt(keyBytes, iv, ciphertext, tag) {
    return this.decryptBytes(keyBytes, hex2buf(iv), hex2buf(ciphertext), hex2buf(tag));
  },

  async encrypt(keyBytes, plaintext) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    const tag = encrypted.slice(encrypted.length - 16);
    return {
      iv: buf2hex(iv),
      ciphertext: buf2hex(ciphertext),
      tag: buf2hex(tag),
    };
  },
};

function buf2hex(buf) {
  return Array.from(buf).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hex2buf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function safeDecodeHeader(value) {
  if (!value) return '';
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return buf2hex(new Uint8Array(digest));
}

// ============ Key Storage (IndexedDB) ============

const KeyStore = {
  DB_NAME: 'syncd',
  STORE_NAME: 'keys',

  async open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(this.STORE_NAME);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },

  async save(key, value) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readwrite');
      tx.objectStore(this.STORE_NAME).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  async get(key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readonly');
      const req = tx.objectStore(this.STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },

  async delete(key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.STORE_NAME, 'readwrite');
      tx.objectStore(this.STORE_NAME).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
};

// ============ DOM Helpers ============

const elements = {
  toasts: document.getElementById('toasts'),
  pairScreen: document.getElementById('pair-screen'),
  mainScreen: document.getElementById('main-screen'),
  pairStatus: document.getElementById('pair-status'),
  pairStatusText: document.getElementById('pair-status-text'),
  pairMeta: document.getElementById('pair-meta'),
  pairSessionState: document.getElementById('pair-session-state'),
  pairDeviceCount: document.getElementById('pair-device-count'),
  pairDeviceName: document.getElementById('device-name-input'),
  pairBtn: document.getElementById('pair-btn'),
  pinInputs: Array.from(document.querySelectorAll('.pin-input')),
  refreshFilesBtn: document.getElementById('refresh-files-btn'),
  toggleSelectionModeBtn: document.getElementById('toggle-selection-mode-btn'),
  fileSearchInput: document.getElementById('file-search-input'),
  fileSortSelect: document.getElementById('file-sort-select'),
  fileList: document.getElementById('file-list'),
  fileSummary: document.getElementById('file-summary'),
  fileRefreshLabel: document.getElementById('file-refresh-label'),
  deviceSummary: document.getElementById('device-summary'),
  deviceSummaryMeta: document.getElementById('device-summary-meta'),
  topSelectionBar: document.getElementById('top-selection-bar'),
  topSelectionText: document.getElementById('top-selection-text'),
  selectAllBtn: document.getElementById('select-all-btn'),
  selectNoneBtn: document.getElementById('select-none-btn'),
  closeTopSelectionBtn: document.getElementById('close-top-selection-btn'),
  selectionBar: document.getElementById('bottom-selection-bar'),
  selectionCount: document.getElementById('selection-count'),
  clearSelectionBtn: document.getElementById('clear-selection-btn'),
  batchDownloadBtn: document.getElementById('batch-download-btn'),
  refreshTextsBtn: document.getElementById('refresh-texts-btn'),
  textInput: document.getElementById('text-input'),
  textHelper: document.getElementById('text-helper'),
  textList: document.getElementById('text-list'),
  sendTextBtn: document.getElementById('send-text-btn'),
};

function toast(message, type = 'info') {
  const element = document.createElement('div');
  element.className = `toast ${type}`;
  element.textContent = message;
  elements.toasts.appendChild(element);
  window.setTimeout(() => element.remove(), 3000);
}

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value;
  return div.innerHTML;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatCountdown(expiresAt) {
  const remainingMs = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) return '00:00';
  const totalSeconds = Math.ceil(remainingMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function downloadBuffer(filename, plainBuf) {
  const blob = new Blob([plainBuf]);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

// ============ Global State ============

const PAGE_SIZE = 100;
const MAX_BROWSER_DOWNLOAD_BYTES = 64 * 1024 * 1024;
const TEXT_REFRESH_MS = 15000;

let encryptionKey = null;
let deviceId = null;
let deviceRecord = null;
let pairing = false;
let textSending = false;

let pairStatusTimer = null;
let pairCountdownTimer = null;
let fileRefreshTimer = null;
let textRefreshTimer = null;
let scrollLoaderObserver = null;
let scrollLoaderTimer = null;
let authResetPromise = null;
let pairStatusLockedUntil = 0;
let pairSessionState = null;

let allEntries = [];
let visibleEntries = [];
let currentPage = 0;
let isRenderingPage = false;
let flatFileMode = false;

let selectionMode = false;
let selectedFiles = new Set();
let loadedTexts = [];

// ============ Networking ============

async function decryptDownloadResponse(response) {
  const streamIv = response.headers.get('x-encrypted-iv');
  if (streamIv) {
    const declaredSize = Number.parseInt(response.headers.get('x-file-size') || '0', 10);
    if (Number.isFinite(declaredSize) && declaredSize > MAX_BROWSER_DOWNLOAD_BYTES) {
      throw new Error(`浏览器暂不支持直接解密超过 ${formatSize(MAX_BROWSER_DOWNLOAD_BYTES)} 的单文件，请改用 Python CLI`);
    }

    const tagLength = Number.parseInt(response.headers.get('x-encrypted-tag-length') || '16', 10);
    const payload = new Uint8Array(await response.arrayBuffer());
    if (payload.length < tagLength) {
      throw new Error('Encrypted payload is truncated');
    }

    const ciphertext = payload.subarray(0, payload.length - tagLength);
    const tag = payload.subarray(payload.length - tagLength);
    const plainBuf = await Crypto.decryptBytes(encryptionKey, hex2buf(streamIv), ciphertext, tag);
    return {
      filename: safeDecodeHeader(response.headers.get('x-file-name')),
      plainBuf,
    };
  }

  const { encrypted } = await response.json();
  return {
    filename: encrypted.filename || '',
    plainBuf: await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag),
  };
}

function buildSignedPath(pathname) {
  const url = new URL(pathname, window.location.origin);
  return url.pathname + url.search;
}

async function deriveRequestAuthKey() {
  if (!encryptionKey || !deviceId) {
    throw new Error('Device is not authenticated');
  }
  return Crypto.hkdf(encryptionKey, 'syncd-request-auth', `device:${deviceId}`);
}

async function maybeHandleAuthFailure(response) {
  if (![401, 403].includes(response.status)) return false;

  let errorMessage = '';
  try {
    const text = await response.clone().text();
    if (text) {
      try {
        errorMessage = JSON.parse(text).error || text.slice(0, 120);
      } catch {
        errorMessage = text.slice(0, 120);
      }
    }
  } catch {
    errorMessage = '';
  }

  const resettableErrors = new Set([
    'Unknown device',
    'Invalid request signature',
    'Missing request authentication headers',
    'Not paired',
  ]);

  if (resettableErrors.has(errorMessage)) {
    await resetStoredSession(errorMessage || '本地配对已失效，请重新输入 PIN');
    return true;
  }

  if (errorMessage === 'Request timestamp expired') {
    toast('设备时间偏差过大，请校准系统时间后重试', 'err');
  }

  return false;
}

async function apiFetch(pathname, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const signedPath = buildSignedPath(pathname);
  const body = options.body ?? '';
  let bodyBytes = new Uint8Array();
  if (typeof body === 'string') {
    bodyBytes = new TextEncoder().encode(body);
  } else if (body instanceof Uint8Array) {
    bodyBytes = body;
  } else if (body instanceof ArrayBuffer) {
    bodyBytes = new Uint8Array(body);
  }

  const timestamp = Date.now().toString();
  const nonce = window.crypto.randomUUID();
  const bodyHash = await sha256Hex(bodyBytes);
  const authKey = await deriveRequestAuthKey();
  const signature = await Crypto.hmac(
    authKey,
    [method, signedPath, timestamp, nonce, bodyHash].join('\n')
  );

  const headers = new Headers(options.headers || {});
  headers.set('X-Device-Id', deviceId);
  headers.set('X-Auth-Timestamp', timestamp);
  headers.set('X-Auth-Nonce', nonce);
  headers.set('X-Auth-Signature', signature);

  const response = await fetch(pathname, { ...options, method, headers });
  await maybeHandleAuthFailure(response);
  return response;
}

// ============ Screen and Timer Management ============

function teardownScrollLoader() {
  if (scrollLoaderObserver) {
    scrollLoaderObserver.disconnect();
    scrollLoaderObserver = null;
  }
  if (scrollLoaderTimer) {
    clearInterval(scrollLoaderTimer);
    scrollLoaderTimer = null;
  }
}

function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach((screen) => screen.classList.remove('active'));
  document.getElementById(screenId).classList.add('active');
}

function stopPairStatusPolling() {
  if (pairStatusTimer) {
    clearInterval(pairStatusTimer);
    pairStatusTimer = null;
  }
  if (pairCountdownTimer) {
    clearInterval(pairCountdownTimer);
    pairCountdownTimer = null;
  }
}

function stopMainTimers() {
  if (fileRefreshTimer) {
    clearInterval(fileRefreshTimer);
    fileRefreshTimer = null;
  }
  if (textRefreshTimer) {
    clearInterval(textRefreshTimer);
    textRefreshTimer = null;
  }
}

function showPairScreen() {
  showScreen('pair-screen');
  stopMainTimers();
  teardownScrollLoader();
  startPairStatusPolling();
}

function showMainScreen() {
  stopPairStatusPolling();
  showScreen('main-screen');
  loadFiles();
  loadTexts();
  if (fileRefreshTimer) clearInterval(fileRefreshTimer);
  fileRefreshTimer = setInterval(loadFiles, 10000);
  if (textRefreshTimer) clearInterval(textRefreshTimer);
  textRefreshTimer = setInterval(loadTexts, TEXT_REFRESH_MS);
}

// ============ Pairing UI ============

function lockPairStatus(ms = 3500) {
  pairStatusLockedUntil = Date.now() + ms;
}

function setStatus(type, text) {
  elements.pairStatus.className = `status-pill ${type}`;
  elements.pairStatusText.textContent = text;
}

function getDefaultDeviceName() {
  const platform = navigator.userAgentData?.platform || navigator.platform || 'Browser';
  const hostname = window.location.hostname || 'device';
  return `${platform} @ ${hostname}`;
}

function updatePairStatusMeta(status) {
  pairSessionState = status;
  elements.pairDeviceCount.textContent = String(status.pairedDeviceCount || 0);

  if (!status.active) {
    elements.pairSessionState.textContent = '未检测到活动 PIN';
    elements.pairMeta.textContent = status.pairedDeviceCount > 0
      ? '服务端已有已配对设备。请在服务端本机运行 node pin.js 生成新的配对 PIN。'
      : '等待服务端生成配对 PIN。首次启动时，PIN 通常会直接打印在服务端终端里。';
    if (Date.now() >= pairStatusLockedUntil && !pairing) {
      setStatus('waiting', '等待新的配对 PIN');
    }
    return;
  }

  const remainingText = `PIN 剩余 ${formatCountdown(status.expiresAt)} · 剩余尝试 ${status.attemptsRemaining}`;
  elements.pairSessionState.textContent = remainingText;
  elements.pairMeta.textContent = '输入服务端当前 PIN 码即可完成加密配对。没有 PIN 时，请在本机运行 node pin.js。';
  if (Date.now() >= pairStatusLockedUntil && !pairing) {
    setStatus('waiting', 'PIN 已就绪，输入后将自动开始配对');
  }
}

function startPairCountdown() {
  if (pairCountdownTimer) clearInterval(pairCountdownTimer);
  pairCountdownTimer = setInterval(() => {
    if (!pairSessionState?.active || !pairSessionState.expiresAt) return;
    elements.pairSessionState.textContent = `PIN 剩余 ${formatCountdown(pairSessionState.expiresAt)} · 剩余尝试 ${pairSessionState.attemptsRemaining}`;
  }, 1000);
}

async function pollPairStatus() {
  try {
    const response = await fetch('/api/pair/status', { cache: 'no-store' });
    const data = await response.json();
    updatePairStatusMeta(data);
    startPairCountdown();
  } catch {
    if (Date.now() >= pairStatusLockedUntil && !pairing) {
      setStatus('error', '无法获取配对状态，请确认服务端正在运行');
    }
    elements.pairSessionState.textContent = '无法连接服务端';
    elements.pairMeta.textContent = '请检查页面地址、服务端进程，或稍后重试。';
  }
}

function startPairStatusPolling() {
  stopPairStatusPolling();
  pollPairStatus();
  pairStatusTimer = setInterval(pollPairStatus, 5000);
}

function resetPinInputs() {
  elements.pinInputs.forEach((input) => {
    input.value = '';
    input.classList.remove('filled', 'shake');
  });
  elements.pairBtn.disabled = true;
}

async function resetStoredSession(message = '本地配对已失效，请重新输入 PIN') {
  if (authResetPromise) return authResetPromise;

  authResetPromise = (async () => {
    encryptionKey = null;
    deviceId = null;
    deviceRecord = null;
    allEntries = [];
    visibleEntries = [];
    loadedTexts = [];
    elements.fileList.innerHTML = '<li class="loading">等待重新配对...</li>';
    elements.textList.innerHTML = '<li class="loading">等待重新配对...</li>';
    elements.fileSummary.textContent = '0 个项目';
    elements.fileRefreshLabel.textContent = '等待重新连接';
    elements.deviceSummary.textContent = '未连接';
    elements.deviceSummaryMeta.textContent = '请重新输入 PIN';

    selectedFiles.clear();
    exitSelectionMode({ clear: true });
    resetPinInputs();

    await Promise.all([
      KeyStore.delete('encryptionKey'),
      KeyStore.delete('deviceId'),
    ]);

    showPairScreen();
    setStatus('error', message);
    lockPairStatus(4000);
    toast(message, 'err');
    setTimeout(() => elements.pinInputs[0]?.focus(), 80);
  })().finally(() => {
    authResetPromise = null;
  });

  return authResetPromise;
}

async function doPairing(pin) {
  if (pairing) return;

  pairing = true;
  elements.pairBtn.disabled = true;

  try {
    setStatus('working', '正在协商密钥...');

    const initRes = await fetch('/api/pair/init', { cache: 'no-store' });
    const initText = await initRes.text();
    let initData = {};
    try {
      initData = initText ? JSON.parse(initText) : {};
    } catch {
      initData = {};
    }
    if (!initRes.ok) {
      throw new Error(initData.error || `Init failed (${initRes.status})`);
    }

    const client = await Crypto.generateKeyPair();
    const serverPub = await Crypto.importPublicKey(initData.serverPublicKey);
    const sharedSecret = await Crypto.deriveSharedSecret(client.keyPair.privateKey, serverPub);
    const authKey = await Crypto.hkdf(sharedSecret, 'syncd-auth', 'pin-verify');
    const proof = await Crypto.hmac(authKey, pin);

    setStatus('working', '正在验证 PIN...');
    const chosenDeviceName = (elements.pairDeviceName.value || getDefaultDeviceName()).trim().slice(0, 80);
    const newDeviceId = `browser-${window.crypto.randomUUID().slice(0, 8)}`;
    const verifyRes = await fetch('/api/pair/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientPublicKey: client.publicKeyHex,
        proof,
        deviceId: newDeviceId,
        deviceName: chosenDeviceName,
        deviceType: 'browser',
      }),
    });
    const verifyText = await verifyRes.text();
    let verifyData = {};
    try {
      verifyData = verifyText ? JSON.parse(verifyText) : {};
    } catch {
      verifyData = {};
    }
    if (!verifyRes.ok) {
      if (verifyData.remaining !== undefined) {
        throw new Error(`PIN 错误，剩余 ${verifyData.remaining} 次尝试`);
      }
      throw new Error(verifyData.error || 'Verification failed');
    }

    const expectedServerProof = await Crypto.hmac(authKey, 'server-confirmed');
    if (verifyData.serverProof !== expectedServerProof) {
      throw new Error('服务端验证失败');
    }

    const transportKey = await Crypto.hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery');
    encryptionKey = await Crypto.decrypt(
      transportKey,
      verifyData.encryptedMasterKey.iv,
      verifyData.encryptedMasterKey.ciphertext,
      verifyData.encryptedMasterKey.tag
    );
    deviceId = newDeviceId;
    await Promise.all([
      KeyStore.save('encryptionKey', buf2hex(encryptionKey)),
      KeyStore.save('deviceId', newDeviceId),
      KeyStore.save('deviceName', chosenDeviceName),
    ]);

    deviceRecord = {
      id: newDeviceId,
      name: chosenDeviceName,
      type: 'browser',
    };
    elements.deviceSummary.textContent = chosenDeviceName;
    elements.deviceSummaryMeta.textContent = newDeviceId;
    setStatus('success', '配对成功');
    lockPairStatus(2500);
    toast('配对成功，正在加载共享内容', 'ok');
    setTimeout(() => showMainScreen(), 300);
  } catch (error) {
    lockPairStatus();
    setStatus('error', error.message);
    elements.pinInputs.forEach((input) => input.classList.add('shake'));
    setTimeout(() => elements.pinInputs.forEach((input) => input.classList.remove('shake')), 450);
    resetPinInputs();
    elements.pinInputs[0]?.focus();
  } finally {
    pairing = false;
  }
}

function setupPinInputs() {
  function getPin() {
    return elements.pinInputs.map((input) => input.value).join('');
  }

  function updateState() {
    const pin = getPin();
    elements.pairBtn.disabled = pin.length !== 6;
    elements.pinInputs.forEach((input) => input.classList.toggle('filled', !!input.value));
    if (pin.length === 6) {
      setTimeout(() => doPairing(pin), 120);
    }
  }

  elements.pinInputs.forEach((input, index) => {
    input.addEventListener('input', (event) => {
      event.target.value = event.target.value.replace(/[^0-9]/g, '');
      if (event.target.value && index < elements.pinInputs.length - 1) {
        elements.pinInputs[index + 1].focus();
      }
      updateState();
    });

    input.addEventListener('keydown', (event) => {
      if (event.key === 'Backspace' && !event.target.value && index > 0) {
        elements.pinInputs[index - 1].focus();
        elements.pinInputs[index - 1].value = '';
        updateState();
      }
    });

    input.addEventListener('paste', (event) => {
      event.preventDefault();
      const pasted = (event.clipboardData.getData('text') || '').replace(/[^0-9]/g, '');
      for (let offset = 0; offset < Math.min(pasted.length, elements.pinInputs.length - index); offset++) {
        elements.pinInputs[index + offset].value = pasted[offset];
      }
      const targetIndex = Math.min(index + pasted.length, elements.pinInputs.length - 1);
      elements.pinInputs[targetIndex].focus();
      updateState();
    });
  });

  elements.pairBtn.addEventListener('click', () => {
    const pin = getPin();
    if (pin.length === 6) doPairing(pin);
  });
}

// ============ Files ============

function updateFileSummary() {
  const fileEntries = allEntries.filter((entry) => entry.type === 'file');
  const totalSize = fileEntries.reduce((sum, entry) => sum + (entry.size || 0), 0);
  elements.fileSummary.textContent = `${fileEntries.length} 个文件 · ${formatSize(totalSize)}`;
  elements.fileRefreshLabel.textContent = `上次刷新 ${new Date().toLocaleTimeString()}`;
}

function updateVisibleEntries() {
  const searchTerm = elements.fileSearchInput.value.trim().toLowerCase();
  const sortValue = elements.fileSortSelect.value;
  flatFileMode = Boolean(searchTerm) || sortValue !== 'tree';

  if (!flatFileMode) {
    visibleEntries = allEntries.slice();
    return;
  }

  visibleEntries = allEntries
    .filter((entry) => entry.type === 'file')
    .filter((entry) => entry.name.toLowerCase().includes(searchTerm))
    .sort((left, right) => {
      if (sortValue === 'modified-desc') {
        return Date.parse(right.modified || 0) - Date.parse(left.modified || 0);
      }
      if (sortValue === 'size-desc') {
        return (right.size || 0) - (left.size || 0);
      }
      return left.name.localeCompare(right.name, 'zh-Hans-CN');
    });
}

function renderSelectionState() {
  const count = selectedFiles.size;
  elements.selectionCount.textContent = String(count);
  elements.batchDownloadBtn.disabled = count === 0;
  if (selectionMode) {
    elements.topSelectionText.textContent = `已选择 ${count} 项`;
  }
}

function syncRenderedSelection() {
  elements.fileList.querySelectorAll('.file-item[data-name]').forEach((item) => {
    const isSelected = selectedFiles.has(item.dataset.name);
    item.classList.toggle('selected', isSelected);
    const checkbox = item.querySelector('.file-checkbox');
    if (checkbox) checkbox.checked = isSelected;
  });
  renderSelectionState();
}

function createFileItemMarkup(entry) {
  const isDir = entry.type === 'dir';
  const depth = flatFileMode ? 0 : Math.min((entry.name.match(/\//g) || []).length, 3);
  const baseName = entry.name.split('/').pop();
  const escapedName = escapeHtml(baseName);
  const escapedFullPath = escapeHtml(entry.name);
  const checkboxId = `file-${btoa(entry.name).replace(/=+$/, '')}`;

  if (isDir) {
    return `<li class="file-item dir-item indent-${depth}" data-dir="${escapedFullPath}">
      <div class="dir-name dir-toggle">
        <svg class="dir-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>
        <span>${escapedName}</span>
      </div>
      <button class="dir-action" data-dir-download="${escapedFullPath}">打包</button>
    </li>`;
  }

  const metaParts = [];
  if (flatFileMode && entry.name !== baseName) {
    metaParts.push(`<div class="file-path">${escapedFullPath}</div>`);
  }
  metaParts.push(`${formatSize(entry.size)} · ${new Date(entry.modified).toLocaleString()}`);

  return `<li class="file-item indent-${depth}" data-name="${escapedFullPath}">
    <input type="checkbox" class="file-checkbox" id="${checkboxId}">
    <label for="${checkboxId}" class="file-checkbox-label">
      <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
    </label>
    <div class="file-content-wrapper">
      <div class="file-name">${escapedName}</div>
      <div class="file-meta">${metaParts.join('')}</div>
    </div>
    <span class="file-dl">下载</span>
  </li>`;
}

function renderEmptyFiles() {
  const searchTerm = elements.fileSearchInput.value.trim();
  if (allEntries.length === 0) {
    elements.fileList.innerHTML = '<li class="empty-state"><div class="empty-icon">📁</div>暂无共享文件<br><span style="font-size:0.72rem;color:var(--text-3)">将文件放入 shared/ 目录即可</span></li>';
    return;
  }

  if (flatFileMode) {
    const message = searchTerm ? '没有匹配当前搜索条件的文件' : '当前筛选结果为空';
    elements.fileList.innerHTML = `<li class="empty-state"><div class="empty-icon">🔎</div>${escapeHtml(message)}<br><span style="font-size:0.72rem;color:var(--text-3)">清空搜索或切回树状视图试试</span></li>`;
    return;
  }

  elements.fileList.innerHTML = '<li class="empty-state"><div class="empty-icon">📁</div>暂无可显示项目</li>';
}

function renderFileList() {
  teardownScrollLoader();
  updateVisibleEntries();
  currentPage = 0;
  elements.fileList.innerHTML = '';
  if (visibleEntries.length === 0) {
    renderEmptyFiles();
    return;
  }
  renderNextPage();
  if (visibleEntries.length > PAGE_SIZE) {
    setupScrollLoader(elements.fileList);
  }
}

function renderNextPage() {
  if (isRenderingPage) return;
  if (currentPage * PAGE_SIZE >= visibleEntries.length) return;
  isRenderingPage = true;

  const loadMore = elements.fileList.querySelector('.load-more');
  if (loadMore) loadMore.remove();

  const start = currentPage * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, visibleEntries.length);
  const fragment = document.createDocumentFragment();
  const temp = document.createElement('div');

  for (let index = start; index < end; index++) {
    temp.innerHTML = createFileItemMarkup(visibleEntries[index]).trim();
    fragment.appendChild(temp.firstChild);
  }

  elements.fileList.appendChild(fragment);
  currentPage += 1;

  if (end < visibleEntries.length) {
    const loadMoreItem = document.createElement('li');
    loadMoreItem.className = 'loading load-more';
    loadMoreItem.textContent = `已加载 ${end}/${visibleEntries.length}，点击或滚动加载更多`;
    loadMoreItem.style.cursor = 'pointer';
    loadMoreItem.addEventListener('click', () => renderNextPage());
    elements.fileList.appendChild(loadMoreItem);
  }

  syncRenderedSelection();
  isRenderingPage = false;
}

function setupScrollLoader(listElement) {
  teardownScrollLoader();

  scrollLoaderObserver = new IntersectionObserver((entries) => {
    if (entries[0]?.isIntersecting) {
      renderNextPage();
    }
  }, { rootMargin: '120px' });

  const observeLoader = () => {
    const loader = listElement.querySelector('.load-more');
    if (loader) scrollLoaderObserver.observe(loader);
  };

  observeLoader();
  scrollLoaderTimer = setInterval(observeLoader, 500);
}

async function loadFiles() {
  elements.refreshFilesBtn.classList.add('spinning');
  setTimeout(() => elements.refreshFilesBtn.classList.remove('spinning'), 600);

  try {
    const response = await apiFetch('/api/files');
    if (!response.ok) throw new Error('Failed to load files');
    const { encrypted } = await response.json();
    const plain = await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag);
    allEntries = JSON.parse(new TextDecoder().decode(plain));
    updateFileSummary();
    renderFileList();
  } catch (error) {
    elements.fileList.innerHTML = `<li class="loading" style="color:var(--error)">${escapeHtml(error.message)}</li>`;
  }
}

function toggleDir(item) {
  if (flatFileMode) return;
  const dirName = item.dataset.dir || '';
  const collapsed = item.classList.toggle('collapsed');
  let sibling = item.nextElementSibling;
  const prefix = `${dirName}/`;
  while (sibling) {
    const name = sibling.dataset.name || sibling.dataset.dir || '';
    if (!name.startsWith(prefix)) break;
    sibling.classList.toggle('dir-child-hidden', collapsed);
    sibling = sibling.nextElementSibling;
  }
}

async function downloadFile(name, element) {
  if (element?.classList.contains('downloading')) return;
  if (element) {
    element.classList.add('downloading');
    const label = element.querySelector('.file-dl');
    if (label) label.textContent = '解密中...';
  }

  try {
    const encodedPath = name.split('/').map(encodeURIComponent).join('/');
    const response = await apiFetch(`/api/files/${encodedPath}`);
    if (!response.ok) throw new Error('Download failed');
    const { filename, plainBuf } = await decryptDownloadResponse(response);
    downloadBuffer(filename || name.split('/').pop(), plainBuf);
    toast(`${name.split('/').pop()} 下载完成`, 'ok');
  } catch (error) {
    toast(`下载失败: ${error.message}`, 'err');
  } finally {
    if (element) {
      element.classList.remove('downloading');
      const label = element.querySelector('.file-dl');
      if (label) label.textContent = '下载';
    }
  }
}

async function downloadArchive(paths, fallbackName) {
  const response = await apiFetch('/api/archive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ paths }),
  });
  if (!response.ok) {
    const body = await response.text();
    let errorMessage = 'Archive download failed';
    try {
      errorMessage = JSON.parse(body).error || errorMessage;
    } catch {
      if (body) errorMessage = body.slice(0, 120);
    }
    throw new Error(errorMessage);
  }
  const { filename, plainBuf } = await decryptDownloadResponse(response);
  downloadBuffer(filename || fallbackName, plainBuf);
}

async function downloadDirectory(dirName, element) {
  if (element?.classList.contains('downloading')) return;
  if (element) element.classList.add('downloading');
  try {
    await downloadArchive([dirName], `${dirName.split('/').pop() || 'folder'}.tar.gz`);
    toast(`${dirName.split('/').pop()} 已打包下载`, 'ok');
  } catch (error) {
    toast(`目录下载失败: ${error.message}`, 'err');
  } finally {
    if (element) element.classList.remove('downloading');
  }
}

// ============ Selection ============

function clearSelection() {
  selectedFiles.clear();
  syncRenderedSelection();
}

function exitSelectionMode({ clear = true } = {}) {
  selectionMode = false;
  elements.fileList.classList.remove('selection-mode');
  elements.selectionBar.classList.remove('active');
  elements.topSelectionBar.classList.remove('active');
  elements.toggleSelectionModeBtn.textContent = '选择';
  if (clear) clearSelection();
  renderSelectionState();
}

function toggleSelection(name, element) {
  if (selectedFiles.has(name)) {
    selectedFiles.delete(name);
  } else {
    selectedFiles.add(name);
  }
  if (element) {
    const selected = selectedFiles.has(name);
    element.classList.toggle('selected', selected);
    const checkbox = element.querySelector('.file-checkbox');
    if (checkbox) checkbox.checked = selected;
  }
  renderSelectionState();
}

function toggleSelectionMode() {
  selectionMode = !selectionMode;
  if (selectionMode) {
    elements.fileList.classList.add('selection-mode');
    elements.selectionBar.classList.add('active');
    elements.topSelectionBar.classList.add('active');
    elements.toggleSelectionModeBtn.textContent = '完成';
    renderSelectionState();
    return;
  }
  exitSelectionMode({ clear: true });
}

function selectAllFiles() {
  visibleEntries
    .filter((entry) => entry.type === 'file')
    .forEach((entry) => selectedFiles.add(entry.name));
  syncRenderedSelection();
}

async function batchDownload() {
  if (selectedFiles.size === 0) return;
  if (selectedFiles.size > 50) {
    toast('批量下载最多选择 50 个文件', 'err');
    return;
  }

  try {
    await downloadArchive(Array.from(selectedFiles), `selected-${Date.now()}.tar.gz`);
    toast(`已打包 ${selectedFiles.size} 个文件`, 'ok');
    clearSelection();
  } catch (error) {
    toast(`批量下载失败: ${error.message}`, 'err');
  }
}

// ============ Text Sharing ============

function renderTexts() {
  if (loadedTexts.length === 0) {
    elements.textList.innerHTML = '<li class="empty-state"><div class="empty-icon">✉️</div>还没有共享文本</li>';
    return;
  }

  elements.textList.innerHTML = loadedTexts.map((item) => `
    <li class="text-item" data-text-id="${escapeHtml(item.id)}">
      <div class="text-item-header">
        <span>${escapeHtml(item.deviceId || 'unknown')}</span>
        <span>${new Date(item.timestamp).toLocaleString()}</span>
      </div>
      <pre class="text-body">${escapeHtml(item.text)}</pre>
      <div class="text-item-actions">
        <button class="btn-secondary" data-copy-text="${escapeHtml(item.id)}">复制</button>
      </div>
    </li>
  `).join('');
}

async function loadTexts() {
  try {
    const response = await apiFetch('/api/texts');
    if (!response.ok) throw new Error('Failed to load texts');
    const data = await response.json();
    const decrypted = [];
    for (const item of (data.texts || []).slice().sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))) {
      try {
        const plain = await Crypto.decrypt(
          encryptionKey,
          item.data.iv,
          item.data.ciphertext,
          item.data.tag
        );
        decrypted.push({
          id: item.id,
          deviceId: item.deviceId,
          timestamp: item.timestamp,
          text: new TextDecoder().decode(plain),
        });
      } catch {
        decrypted.push({
          id: item.id,
          deviceId: item.deviceId,
          timestamp: item.timestamp,
          text: '[解密失败]',
        });
      }
    }
    loadedTexts = decrypted;
    renderTexts();
  } catch (error) {
    elements.textList.innerHTML = `<li class="loading" style="color:var(--error)">${escapeHtml(error.message)}</li>`;
  }
}

async function sendText() {
  if (textSending) return;
  const value = elements.textInput.value.trim();
  if (!value) {
    toast('先输入一段文本再发送', 'info');
    return;
  }

  textSending = true;
  elements.sendTextBtn.disabled = true;
  elements.textHelper.textContent = '正在加密并发送文本...';

  try {
    const encryptedText = await Crypto.encrypt(encryptionKey, new TextEncoder().encode(value));
    const response = await apiFetch('/api/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ encryptedText }),
    });
    if (!response.ok) throw new Error('Failed to share text');
    elements.textInput.value = '';
    elements.textHelper.textContent = '已发送，最近 24 小时最多保留 100 条文本';
    toast('文本已发送', 'ok');
    await loadTexts();
  } catch (error) {
    elements.textHelper.textContent = `发送失败: ${error.message}`;
    toast(`文本发送失败: ${error.message}`, 'err');
  } finally {
    textSending = false;
    elements.sendTextBtn.disabled = false;
  }
}

async function copySharedText(textId) {
  const item = loadedTexts.find((entry) => entry.id === textId);
  if (!item) return;
  try {
    await navigator.clipboard.writeText(item.text);
    toast('文本已复制', 'ok');
  } catch {
    toast('复制失败，请检查剪贴板权限', 'err');
  }
}

// ============ Event Wiring ============

function setupEventListeners() {
  elements.refreshFilesBtn.addEventListener('click', () => loadFiles());
  elements.toggleSelectionModeBtn.addEventListener('click', toggleSelectionMode);
  elements.selectAllBtn.addEventListener('click', selectAllFiles);
  elements.selectNoneBtn.addEventListener('click', clearSelection);
  elements.clearSelectionBtn.addEventListener('click', clearSelection);
  elements.closeTopSelectionBtn.addEventListener('click', () => exitSelectionMode({ clear: true }));
  elements.batchDownloadBtn.addEventListener('click', batchDownload);
  elements.refreshTextsBtn.addEventListener('click', () => loadTexts());
  elements.sendTextBtn.addEventListener('click', sendText);

  elements.fileSearchInput.addEventListener('input', () => renderFileList());
  elements.fileSortSelect.addEventListener('change', () => renderFileList());

  elements.pairDeviceName.addEventListener('change', () => {
    const value = elements.pairDeviceName.value.trim().slice(0, 80);
    elements.pairDeviceName.value = value;
    KeyStore.save('deviceName', value || getDefaultDeviceName()).catch(() => {});
  });

  elements.fileList.addEventListener('click', (event) => {
    const dirButton = event.target.closest('[data-dir-download]');
    if (dirButton) {
      event.stopPropagation();
      const row = dirButton.closest('.file-item');
      downloadDirectory(dirButton.getAttribute('data-dir-download'), row);
      return;
    }

    const dirToggle = event.target.closest('.dir-toggle');
    if (dirToggle) {
      event.stopPropagation();
      toggleDir(dirToggle.closest('.file-item'));
      return;
    }

    const checkbox = event.target.closest('.file-checkbox, .file-checkbox-label');
    if (checkbox) {
      const row = checkbox.closest('.file-item');
      if (row?.dataset.name) {
        event.stopPropagation();
        toggleSelection(row.dataset.name, row);
      }
      return;
    }

    const row = event.target.closest('.file-item');
    if (!row || row.classList.contains('dir-item') || !row.dataset.name) return;

    if (selectionMode) {
      toggleSelection(row.dataset.name, row);
      return;
    }

    downloadFile(row.dataset.name, row);
  });

  elements.textList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-copy-text]');
    if (!button) return;
    copySharedText(button.getAttribute('data-copy-text'));
  });
}

// ============ Init ============

async function init() {
  setupPinInputs();
  setupEventListeners();

  const storedDeviceName = await KeyStore.get('deviceName');
  elements.pairDeviceName.value = storedDeviceName || getDefaultDeviceName();
  elements.textHelper.textContent = '最近 24 小时最多保留 100 条文本';

  const storedKey = await KeyStore.get('encryptionKey');
  const storedDeviceId = await KeyStore.get('deviceId');
  if (storedKey && storedDeviceId) {
    try {
      encryptionKey = hex2buf(storedKey);
      deviceId = storedDeviceId;
      const sessionResponse = await apiFetch('/api/session');
      if (sessionResponse.ok) {
        const session = await sessionResponse.json();
        deviceRecord = session.device;
        elements.deviceSummary.textContent = session.device?.name || storedDeviceName || storedDeviceId;
        elements.deviceSummaryMeta.textContent = session.device?.id || storedDeviceId;
        showMainScreen();
        return;
      }
    } catch {
      encryptionKey = null;
      deviceId = null;
      deviceRecord = null;
    }
  }

  showPairScreen();
  setTimeout(() => elements.pinInputs[0]?.focus(), 80);
}

init();
