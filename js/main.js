// main.js - AES-GCM (text + file) with safer defaults and memory hygiene
// Assumes DOM elements with IDs used in your app already exist.

// -------------------- Utilities / UI --------------------
function showToast(msg, type = 'info') {
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.textContent = msg;
  const cont = document.getElementById('toast-container');
  if (cont) cont.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

// Converters
function bufToBase64(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function base64ToBuf(s) {
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

function bufToHex(buf) {
  const b = new Uint8Array(buf);
  let out = '';
  for (const x of b) {
    let h = x.toString(16);
    if (h.length === 1) h = '0' + h;
    out += h;
  }
  return out;
}

function hexToBuf(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex');
  const arr = new Uint8Array(clean.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(clean.substr(i * 2, 2), 16);
  return arr.buffer;
}

function bufToBytesString(buf) {
  return Array.from(new Uint8Array(buf)).join(',');
}

function bytesStringToBuf(s) {
  const parts = s.split(/[,\s]+/).filter(x => x);
  const arr = new Uint8Array(parts.length);
  for (let i = 0; i < parts.length; i++) {
    const n = Number(parts[i]);
    if (!Number.isFinite(n) || n < 0 || n > 255) throw new Error('Invalid byte at ' + i);
    arr[i] = n;
  }
  return arr.buffer;
}

// write/read big-endian uint32
function writeUint32BE(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function readUint32BE(bytes, off) {
  return (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
}

// zeroing helper
function zeroBuf(u8) {
  try { if (u8 && typeof u8.fill === 'function') u8.fill(0); } catch (e) { /* best-effort */ }
}

// -------------------- Crypto primitives --------------------
// deriveKeyFromPassword(passStr, saltUint8, iterations) -> CryptoKey
async function deriveKeyFromPassword(passStr, saltUint8, iterations) {
  if (!(saltUint8 instanceof Uint8Array)) throw new Error('salt must be Uint8Array');
  const enc = new TextEncoder();
  const passBytes = enc.encode(passStr); // Uint8Array
  try {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      passBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltUint8,
        iterations: iterations,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  } finally {
    // wipe pass bytes
    zeroBuf(passBytes);
  }
}

// AES-GCM encrypt/decrypt with explicit tagLength and versioned file format
// File format: version(1) || salt(16) || iv(12) || ciphertext...
const FORMAT_VERSION = 1;

async function aesEncryptPayload(rawBuf, pass, iterations) {
  // inputs: rawBuf = ArrayBuffer/TypedArray, pass = string, iterations = Number
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(pass, salt, iterations);
  const algo = { name: 'AES-GCM', iv: iv, tagLength: 128 };
  const ct = await crypto.subtle.encrypt(algo, key, rawBuf);

  const ctArr = new Uint8Array(ct);
  // build combined: 1 + 16 + 12 + ct
  const combined = new Uint8Array(1 + 16 + 12 + ctArr.byteLength);
  combined[0] = FORMAT_VERSION;
  combined.set(salt, 1);
  combined.set(iv, 1 + 16);
  combined.set(ctArr, 1 + 16 + 12);

  // wipe temp arrays (salt/iv/ctArr) - combined holds the data for output
  zeroBuf(salt);
  zeroBuf(iv);
  zeroBuf(ctArr);

  return combined.buffer; // ArrayBuffer
}

async function aesDecryptPayload(combinedBuf, pass, iterations) {
  const combined = new Uint8Array(combinedBuf);
  if (combined.length < (1 + 16 + 12 + 1)) throw new Error('Input too short');

  // detect versioned format
  let offset = 0;
  let version = combined[0];
  let salt, iv, ctArr;
  if (version === FORMAT_VERSION) {
    offset = 1;
    salt = combined.slice(offset, offset + 16);
    offset += 16;
    iv = combined.slice(offset, offset + 12);
    offset += 12;
    ctArr = combined.slice(offset);
  } else {
    // backward compatible: old format (no version byte): salt@0, iv@16, ct@28
    version = 0;
    salt = combined.slice(0, 16);
    iv = combined.slice(16, 28);
    ctArr = combined.slice(28);
  }

  const key = await deriveKeyFromPassword(pass, salt, iterations);
  const algo = { name: 'AES-GCM', iv: iv, tagLength: 128 };
  try {
    const plain = await crypto.subtle.decrypt(algo, key, ctArr.buffer);
    // wipe temps
    zeroBuf(salt);
    zeroBuf(iv);
    zeroBuf(ctArr);
    return plain; // ArrayBuffer
  } catch (err) {
    // wipe temps on failure
    zeroBuf(salt);
    zeroBuf(iv);
    zeroBuf(ctArr);
    console.warn('aesDecryptPayload error (masked to user):', err);
    throw new Error('Decryption failed.');
  }
}

// -------------------- DOM refs --------------------
const plainEl = document.getElementById('plain');
const outEl = document.getElementById('out');
const passEl = document.getElementById('pass');
const itersEl = document.getElementById('iters');
const encSel = document.getElementById('encoding');
const fileInput = document.getElementById('fileInput');

// iteration helper: enforce min/default/max
function normalizeIters(rawVal) {
  const DEFAULT = 200000;
  const MIN = 100000;
  const MAX = 1000000;
  const n = Number(rawVal) || DEFAULT;
  return Math.min(MAX, Math.max(MIN, Math.floor(n)));
}

// -------------------- Text handlers --------------------
document.getElementById('encryptText').addEventListener('click', async () => {
  try {
    const pass = passEl.value;
    if (!pass) { showToast('Enter passphrase', 'warning'); return; }
    const iters = normalizeIters(itersEl.value);
    const raw = new TextEncoder().encode(plainEl.value);
    const combined = await aesEncryptPayload(raw.buffer, pass, iters);

    let out = '';
    if (encSel.value === 'base64') out = bufToBase64(combined);
    else if (encSel.value === 'hex') out = bufToHex(combined);
    else out = bufToBytesString(combined);

    outEl.value = out;
    // wipe plaintext typedarray
    zeroBuf(raw);
    showToast('Text encrypted', 'success');
  } catch (e) {
    console.warn('encryptText error:', e);
    showToast('Encrypt failed.', 'error');
  }
});

document.getElementById('decryptText').addEventListener('click', async () => {
  try {
    const pass = passEl.value;
    if (!pass) { showToast('Enter passphrase', 'warning'); return; }
    const iters = normalizeIters(itersEl.value);
    const input = plainEl.value.trim();
    if (!input) { showToast('Paste encoded input', 'warning'); return; }

    let buf;
    if (encSel.value === 'base64') buf = base64ToBuf(input);
    else if (encSel.value === 'hex') buf = hexToBuf(input);
    else buf = bytesStringToBuf(input);

    const plainBuf = await aesDecryptPayload(buf, pass, iters);
    outEl.value = new TextDecoder().decode(plainBuf);

    // wipe plaintext array
    if (plainBuf && plainBuf.byteLength) {
      zeroBuf(new Uint8Array(plainBuf));
    }

    showToast('Text decrypted', 'success');
  } catch (e) {
    console.warn('decryptText user error:', e);
    showToast('Decryption failed.', 'error');
  }
});

// Copy Button
document.getElementById('copyOut').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(outEl.value);
    showToast('Copied', 'info');
  } catch (e) {
    showToast('Copy failed', 'error');
  }
});

// Clear All Button
document.getElementById('clearText').addEventListener('click', () => {
  plainEl.value = '';
  outEl.value = '';
  passEl.value = '';
  if (fileInput) fileInput.value = '';
  showToast('All Input cleared', 'info');
});

// Download encrypted text (outEl contains encoded string per encSel)
document.getElementById('downloadTextEnc').addEventListener('click', async () => {
  try {
    if (!outEl.value) { showToast('Nothing to download', 'warning'); return; }
    let buf;
    if (encSel.value === 'base64') buf = base64ToBuf(outEl.value);
    else if (encSel.value === 'hex') buf = hexToBuf(outEl.value);
    else buf = bytesStringToBuf(outEl.value);

    const filename = prompt('Filename for download', 'message.aes') || 'message.aes';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([buf]));
    a.download = filename;
    a.click();
    showToast('Downloaded', 'success');
  } catch (e) {
    console.warn('downloadTextEnc error:', e);
    showToast('Download failed', 'error');
  }
});

// Upload encrypted text into input (loads as base64)
document.getElementById('uploadTextEnc').addEventListener('click', () => {
  const f = document.createElement('input');
  f.type = 'file';
  f.accept = '.aes';
  f.onchange = async () => {
    const file = f.files[0];
    if (!file) { showToast('No file', 'warning'); return; }
    const buf = await file.arrayBuffer();
    plainEl.value = bufToBase64(buf);
    encSel.value = 'base64';
    outEl.value = '';
    showToast('Loaded into input', 'info');
  };
  f.click();
});

// -------------------- File handlers --------------------
async function encryptFile() {
  const f = fileInput.files[0];
  if (!f) { showToast('Select a file', 'warning'); return; }
  const pass = passEl.value;
  if (!pass) { showToast('Enter passphrase', 'warning'); return; }
  const iters = normalizeIters(itersEl.value);

  try {
    const fileBuf = await f.arrayBuffer();
    const meta = { origName: f.name };
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const metaLen = writeUint32BE(metaBytes.length);

    // payload = metaLen(4) + metaBytes + fileBuf
    const payload = new Uint8Array(4 + metaBytes.length + fileBuf.byteLength);
    payload.set(metaLen, 0);
    payload.set(metaBytes, 4);
    payload.set(new Uint8Array(fileBuf), 4 + metaBytes.length);

    const combined = await aesEncryptPayload(payload.buffer, pass, iters);

    let baseDefault = f.name.replace(/\.[^\.]+$/, '');
    let base = prompt('Enter base name for encrypted file (no extension)', baseDefault);
    if (base === null) { showToast('Cancelled', 'info'); return; }
    base = base.replace(/\.[^\.]+$/, '');
    const outName = base + '.enc';

    const blob = new Blob([combined], { type: 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = outName;
    a.click();

    // wipe temp payload
    zeroBuf(payload);
    zeroBuf(metaBytes);

    showToast('Saved ' + outName, 'success');
  } catch (e) {
    console.warn('encryptFile error:', e);
    showToast('Encrypt failed.', 'error');
  }
}

async function decryptFile() {
  const f = fileInput.files[0];
  if (!f) { showToast('Select a file', 'warning'); return; }
  const pass = passEl.value;
  if (!pass) { showToast('Enter passphrase', 'warning'); return; }
  const iters = normalizeIters(itersEl.value);

  try {
    const combinedBuf = await f.arrayBuffer();
    const payloadBuf = await aesDecryptPayload(combinedBuf, pass, iters);
    const payload = new Uint8Array(payloadBuf);

    if (payload.length < 4) {
      showToast('Invalid payload', 'error');
      return;
    }
    const metaLen = readUint32BE(payload, 0);
    const metaStart = 4;
    const metaEnd = 4 + metaLen;
    if (metaEnd > payload.length) { showToast('Invalid metadata length', 'error'); return; }

    const metaBytes = payload.slice(metaStart, metaEnd);
    let meta;
    try {
      meta = JSON.parse(new TextDecoder().decode(metaBytes));
    } catch {
      showToast('Bad metadata', 'error');
      return;
    }

    const fileBytes = payload.slice(metaEnd).buffer;
    const origName = meta.origName || 'decrypted_file';
    const extMatch = origName.match(/(\.[^\.]+)$/);
    const ext = extMatch ? extMatch[1] : '';
    const origBase = origName.replace(/\.[^\.]+$/, '');
    let base = prompt('Save as (base name only). Original extension will be restored:', origBase);
    if (base === null) { showToast('Cancelled', 'info'); return; }
    base = base.replace(/\.[^\.]+$/, '');
    const outName = base + ext;

    const blob = new Blob([fileBytes], { type: 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = outName;
    a.click();

    // wipe payload
    zeroBuf(payload);
    zeroBuf(metaBytes);

    showToast('Saved ' + outName, 'success');
  } catch (e) {
    console.warn('decryptFile error:', e);
    showToast('Decryption failed.', 'error');
  }
}

// UI wiring
document.getElementById('encryptFile').addEventListener('click', encryptFile);
document.getElementById('decryptFile').addEventListener('click', decryptFile);
document.getElementById('uploadFileEnc').addEventListener('click', () => {
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = '.enc';
  inp.onchange = () => {
    fileInput.files = inp.files;
    showToast('File ready', 'info');
  };
  inp.click();
});

// Paste button
document.getElementById('pasteInput').addEventListener('click', async () => {
  try {
    plainEl.value = '';
    outEl.value = '';
    const text = await navigator.clipboard.readText();
    if (!text) { showToast('Clipboard empty', 'warning'); return; }
    plainEl.value = text;
    showToast('Pasted from clipboard', 'info');
  } catch (e) {
    console.warn('pasteInput error:', e);
    showToast('Paste failed.', 'error');
  }
});

// Clear Input button (keeps passphrase)
document.getElementById('clearInput').addEventListener('click', () => {
  plainEl.value = '';
  outEl.value = '';
  showToast('Input cleared', 'info');
});