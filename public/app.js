// ============ Crypto Utilities (Web Crypto API) ============

const Crypto = {
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const pubRaw = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
    return { keyPair, publicKeyHex: buf2hex(new Uint8Array(pubRaw)) };
  },

  async importPublicKey(hex) {
    return window.crypto.subtle.importKey(
      'raw', hex2buf(hex), { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
  },

  async deriveSharedSecret(privateKey, publicKey) {
    const bits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey }, privateKey, 256
    );
    return new Uint8Array(bits);
  },

  async hkdf(ikm, salt, info, length = 32) {
    const baseKey = await window.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await window.crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new TextEncoder().encode(salt),
      info: new TextEncoder().encode(info),
    }, baseKey, length * 8);
    return new Uint8Array(bits);
  },

  async hmac(key, data) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await window.crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
    return buf2hex(new Uint8Array(sig));
  },

  async decrypt(keyBytes, iv, ciphertext, tag) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const ctBuf = hex2buf(ciphertext), tagBuf = hex2buf(tag);
    const combined = new Uint8Array(ctBuf.length + tagBuf.length);
    combined.set(ctBuf); combined.set(tagBuf, ctBuf.length);
    return new Uint8Array(await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: hex2buf(iv) }, key, combined));
  },

  async encrypt(keyBytes, plaintext) {
    const key = await window.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encBuf = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
    const ciphertext = encBuf.slice(0, encBuf.length - 16);
    const tag = encBuf.slice(encBuf.length - 16);
    return { iv: buf2hex(iv), ciphertext: buf2hex(ciphertext), tag: buf2hex(tag) };
  },
};

function buf2hex(buf) { return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''); }
function hex2buf(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}

// ============ Key Storage (IndexedDB) ============

const KeyStore = {
  DB_NAME: 'syncd', STORE_NAME: 'keys',
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
};

// ============ Toast Notifications ============

function toast(msg, type = 'info') {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

// ============ Screen Management ============

let encryptionKey = null;
let fileRefreshTimer = null;

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
  });
  const el = document.getElementById(id);
  void el.offsetHeight;
  el.classList.add('active');
}

function showMainScreen() {
  showScreen('main-screen');
  loadFiles();
  if (fileRefreshTimer) clearInterval(fileRefreshTimer);
  fileRefreshTimer = setInterval(loadFiles, 10000);
}

function showPairScreen() {
  showScreen('pair-screen');
  if (fileRefreshTimer) { clearInterval(fileRefreshTimer); fileRefreshTimer = null; }
}

// ============ Pairing Flow ============

let pairing = false;

function setStatus(type, text) {
  const pill = document.getElementById('pair-status');
  const textEl = document.getElementById('pair-status-text');
  pill.className = `status-pill ${type}`;
  textEl.textContent = text;
}

async function doPairing(pin) {
  if (pairing) return;
  pairing = true;
  const btn = document.getElementById('pair-btn');
  const inputs = document.querySelectorAll('.pin-input');
  btn.disabled = true;

  try {
    setStatus('working', '正在协商密钥...');

    const initRes = await fetch('/api/pair/init');
    if (!initRes.ok) {
      const text = await initRes.text();
      let msg = `Init failed (${initRes.status})`;
      try { msg = JSON.parse(text).error || msg; } catch { msg += ': ' + text.slice(0, 100); }
      throw new Error(msg);
    }
    const { serverPublicKey } = await initRes.json();

    const client = await Crypto.generateKeyPair();
    const serverPub = await Crypto.importPublicKey(serverPublicKey);
    const sharedSecret = await Crypto.deriveSharedSecret(client.keyPair.privateKey, serverPub);

    const authKey = await Crypto.hkdf(sharedSecret, 'syncd-auth', 'pin-verify');
    const proof = await Crypto.hmac(authKey, pin);

    setStatus('working', '正在验证 PIN...');
    const deviceId = 'browser-' + Math.random().toString(36).slice(2, 8);
    const verifyRes = await fetch('/api/pair/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientPublicKey: client.publicKeyHex, proof, deviceId }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json();
      if (err.remaining !== undefined) throw new Error(`PIN 错误，剩余 ${err.remaining} 次尝试`);
      throw new Error(err.error || 'Verification failed');
    }

    const { serverProof, encryptedMasterKey } = await verifyRes.json();
    const expectedServerProof = await Crypto.hmac(authKey, 'server-confirmed');
    if (serverProof !== expectedServerProof) throw new Error('服务端验证失败');

    const transportKey = await Crypto.hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery');
    encryptionKey = await Crypto.decrypt(
      transportKey, encryptedMasterKey.iv, encryptedMasterKey.ciphertext, encryptedMasterKey.tag
    );
    await KeyStore.save('encryptionKey', buf2hex(encryptionKey));
    await KeyStore.save('deviceId', deviceId);

    setStatus('success', '配对成功');
    setTimeout(() => showMainScreen(), 500);

  } catch (err) {
    setStatus('error', err.message);
    inputs.forEach(el => { el.classList.add('shake'); el.value = ''; });
    setTimeout(() => inputs.forEach(el => el.classList.remove('shake')), 500);
    inputs[0].focus();
    btn.disabled = true;
  } finally {
    pairing = false;
  }
}

// ============ File Operations ============

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

const PAGE_SIZE = 100;
let allEntries = [];
let currentPage = 0;
let isLoading = false;

async function loadFiles() {
  const listEl = document.getElementById('file-list');
  const btn = document.getElementById('refresh-files-btn');

  if (btn) { btn.classList.add('spinning'); setTimeout(() => btn.classList.remove('spinning'), 600); }

  try {
    const res = await fetch('/api/files');
    if (!res.ok) throw new Error('Failed to load files');
    const { encrypted } = await res.json();

    const plainBuf = await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag);
    allEntries = JSON.parse(new TextDecoder().decode(plainBuf));
    currentPage = 0;
    
    listEl.innerHTML = '';
    if (allEntries.length === 0) {
      listEl.innerHTML = '<li class="empty-state"><div class="empty-icon">📁</div>暂无共享文件<br><span style="font-size:0.72rem;color:var(--text-3)">将文件放入 shared/ 目录即可</span></li>';
      return;
    }

    renderNextPage();
    
    if (allEntries.length > PAGE_SIZE) {
      setupScrollLoader(listEl);
    }
  } catch (err) {
    listEl.innerHTML = `<li class="loading" style="color:var(--error)">${escapeHtml(err.message)}</li>`;
  }
}

function renderNextPage() {
  if (isLoading || currentPage * PAGE_SIZE >= allEntries.length) return;
  isLoading = true;
  
  const listEl = document.getElementById('file-list');
  const loadMoreEl = listEl.querySelector('.load-more');
  if (loadMoreEl) loadMoreEl.remove();
  
  const start = currentPage * PAGE_SIZE;
  const end = Math.min(start + PAGE_SIZE, allEntries.length);
  
  for (let i = start; i < end; i++) {
    const entry = allEntries[i];
    const depth = (entry.name.match(/\//g) || []).length;
    const indent = Math.min(depth, 3);
    const baseName = entry.name.split('/').pop();
    const li = document.createElement('li');

    if (entry.type === 'dir') {
      li.className = `file-item dir-item indent-${indent}`;
      li.innerHTML = `<div class="dir-name"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>${escapeHtml(baseName)}</div>`;
    } else {
      li.className = `file-item indent-${indent}`;
      li.dataset.name = entry.name;
      li.innerHTML = `<div><div class="file-name">${escapeHtml(baseName)}</div><div class="file-meta">${formatSize(entry.size)} · ${new Date(entry.modified).toLocaleString()}</div></div><span class="file-dl">下载</span>`;
      li.onclick = () => downloadFile(entry.name, li);
    }
    listEl.appendChild(li);
  }
  
  currentPage++;
  
  if (end < allEntries.length) {
    const loadMoreLi = document.createElement('li');
    loadMoreLi.className = 'loading load-more';
    loadMoreLi.textContent = `已加载 ${end}/${allEntries.length}，点击或滚动加载更多`;
    loadMoreLi.style.cursor = 'pointer';
    loadMoreLi.onclick = () => { isLoading = false; renderNextPage(); };
    listEl.appendChild(loadMoreLi);
  }
  
  isLoading = false;
}

function setupScrollLoader(listEl) {
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !isLoading) {
      const loadMoreEl = listEl.querySelector('.load-more');
      if (loadMoreEl) renderNextPage();
    }
  }, { rootMargin: '100px' });
  
  const checkLoader = () => {
    const loadMoreEl = listEl.querySelector('.load-more');
    if (loadMoreEl) observer.observe(loadMoreEl);
  };
  checkLoader();
  setInterval(checkLoader, 500);
}

async function downloadFile(name, li) {
  if (li.classList.contains('downloading')) return;
  li.classList.add('downloading');
  li.querySelector('.file-dl').textContent = '解密中...';

  try {
    // Encode each path segment separately to preserve slashes
    const encodedPath = name.split('/').map(encodeURIComponent).join('/');
    const res = await fetch(`/api/files/${encodedPath}`);
    if (!res.ok) throw new Error('Download failed');
    const { encrypted } = await res.json();

    const plainBuf = await Crypto.decrypt(encryptionKey, encrypted.iv, encrypted.ciphertext, encrypted.tag);

    const blob = new Blob([plainBuf]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name.split('/').pop();
    a.click();
    URL.revokeObjectURL(url);
    toast(`${name.split('/').pop()} 下载完成`, 'ok');
  } catch (err) {
    toast('下载失败: ' + err.message, 'err');
  } finally {
    li.classList.remove('downloading');
    li.querySelector('.file-dl').textContent = '下载';
  }
}

// ============ PIN Input ============

function setupPinInputs() {
  const inputs = document.querySelectorAll('.pin-input');
  const btn = document.getElementById('pair-btn');

  function getPin() { return Array.from(inputs).map(el => el.value).join(''); }

  function updateState() {
    const pin = getPin();
    btn.disabled = pin.length !== 6;
    inputs.forEach(el => el.classList.toggle('filled', !!el.value));
    if (pin.length === 6) {
      setTimeout(() => doPairing(pin), 150);
    }
  }

  inputs.forEach((input, i) => {
    input.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/[^0-9]/g, '');
      if (e.target.value && i < inputs.length - 1) inputs[i + 1].focus();
      updateState();
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && i > 0) {
        inputs[i - 1].focus();
        inputs[i - 1].value = '';
        updateState();
      }
    });

    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData.getData('text') || '').replace(/[^0-9]/g, '');
      for (let j = 0; j < Math.min(pasted.length, inputs.length - i); j++) {
        inputs[i + j].value = pasted[j];
      }
      inputs[Math.min(i + pasted.length, inputs.length - 1)].focus();
      updateState();
    });
  });

  btn.addEventListener('click', () => {
    const pin = getPin();
    if (pin.length === 6) doPairing(pin);
  });
}

// ============ Init ============

async function init() {
  setupPinInputs();

  const storedKey = await KeyStore.get('encryptionKey');
  if (storedKey) {
    try {
      const statusRes = await fetch('/api/status');
      const { paired } = await statusRes.json();
      if (paired) {
        encryptionKey = hex2buf(storedKey);
        showMainScreen();
        return;
      }
    } catch { /* server not paired */ }
  }

  showPairScreen();
  setTimeout(() => document.querySelector('.pin-input').focus(), 100);
}

init();
