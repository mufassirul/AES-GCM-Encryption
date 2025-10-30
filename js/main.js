// Toast
function showToast(msg, type = 'info') {
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    document.getElementById('toast-container').appendChild(t);
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

// Crypto helpers (WebCrypto)
async function deriveKey(pass, salt, iters) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(pass), { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: iters, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function aesEncrypt(rawBuf, pass, iters) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pass, salt.buffer, iters);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, rawBuf);
    const combined = new Uint8Array(16 + 12 + ct.byteLength);
    combined.set(salt, 0);
    combined.set(iv, 16);
    combined.set(new Uint8Array(ct), 28);
    return combined.buffer;
}

async function aesDecrypt(combinedBuf, pass, iters) {
    const combined = new Uint8Array(combinedBuf);
    if (combined.length < 29) throw new Error('Input too short');
    const salt = combined.slice(0, 16).buffer;
    const iv = combined.slice(16, 28).buffer;
    const ct = combined.slice(28).buffer;
    const key = await deriveKey(pass, salt, iters);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, ct);
}

// Header helpers for packed payload
function writeUint32BE(n) {
    return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function readUint32BE(bytes, off) {
    return (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
}

// DOM refs
const plainEl = document.getElementById('plain');
const outEl = document.getElementById('out');
const passEl = document.getElementById('pass');
const itersEl = document.getElementById('iters');
const encSel = document.getElementById('encoding');
const fileInput = document.getElementById('fileInput');

// --- Text handlers ---
document.getElementById('encryptText').addEventListener('click', async () => {
    try {
        const pass = passEl.value;
        if (!pass) {
            showToast('Enter passphrase', 'warning');
            return;
        }
        const iters = Math.max(1000, Number(itersEl.value) || 150000);
        const raw = new TextEncoder().encode(plainEl.value);
        const combined = await aesEncrypt(raw, pass, iters);
        let out = '';
        if (encSel.value === 'base64') out = bufToBase64(combined);
        else if (encSel.value === 'hex') out = bufToHex(combined);
        else out = bufToBytesString(combined);
        outEl.value = out;
        showToast('Text encrypted', 'success');
    } catch (e) {
        showToast('Encrypt failed: ' + e.message, 'error');
    }
});

document.getElementById('decryptText').addEventListener('click', async () => {
    try {
        const pass = passEl.value;
        if (!pass) {
            showToast('Enter passphrase', 'warning');
            return;
        }
        const iters = Math.max(1000, Number(itersEl.value) || 150000);
        const input = plainEl.value.trim();
        if (!input) {
            showToast('Paste encoded input', 'warning');
            return;
        }
        let buf;
        if (encSel.value === 'base64') buf = base64ToBuf(input);
        else if (encSel.value === 'hex') buf = hexToBuf(input);
        else buf = bytesStringToBuf(input);
        const plainBuf = await aesDecrypt(buf, pass, iters);
        outEl.value = new TextDecoder().decode(plainBuf);
        showToast('Text decrypted', 'success');
    } catch (e) {
        showToast('Decrypt failed: ' + e.message, 'error');
    }
});

// Copy Button
document.getElementById('copyOut').addEventListener('click', () => {
    navigator.clipboard.writeText(outEl.value);
    showToast('Copied', 'info');
});

// Clear All Button
document.getElementById('clearText').addEventListener('click', () => {
    plainEl.value = '';
    outEl.value = '';
    passEl.value = '';
    fileInput.value = '';
    showToast('All Input cleared', 'info');
});

// Download encrypted text
document.getElementById('downloadTextEnc').addEventListener('click', async () => {
    try {
        if (!outEl.value) {
            showToast('Nothing to download', 'warning');
            return;
        }
        let buf;
        if (encSel.value === 'base64') buf = base64ToBuf(outEl.value);
        else if (encSel.value === 'hex') buf = hexToBuf(outEl.value);
        else buf = bytesStringToBuf(outEl.value);
        const filename = prompt('Filename for download', 'message.enc') || 'message.enc';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([buf]));
        a.download = filename;
        a.click();
        showToast('Downloaded', 'success');
    } catch (e) {
        showToast('Download failed: ' + e.message, 'error');
    }
});

// Upload encrypted text
document.getElementById('uploadTextEnc').addEventListener('click', () => {
    const f = document.createElement('input');
    f.type = 'file';
    f.accept = '.enc';
    f.onchange = async () => {
        const file = f.files[0];
        if (!file) {
            showToast('No file', 'warning');
            return;
        }
        const buf = await file.arrayBuffer();
        plainEl.value = bufToBase64(buf);
        encSel.value = 'base64';
        outEl.value = '';
        showToast('Loaded into input', 'info');
    };
    f.click();
});

// --- File handlers ---
async function encryptFile() {
    const f = fileInput.files[0];
    if (!f) {
        showToast('Select a file', 'warning');
        return;
    }
    const pass = passEl.value;
    if (!pass) {
        showToast('Enter passphrase', 'warning');
        return;
    }
    const iters = Math.max(1000, Number(itersEl.value) || 150000);
    try {
        const fileBuf = await f.arrayBuffer();
        const meta = { origName: f.name };
        const metaStr = JSON.stringify(meta);
        const metaBytes = new TextEncoder().encode(metaStr);
        const metaLen = writeUint32BE(metaBytes.length);
        const payload = new Uint8Array(4 + metaBytes.length + fileBuf.byteLength);
        payload.set(metaLen, 0);
        payload.set(metaBytes, 4);
        payload.set(new Uint8Array(fileBuf), 4 + metaBytes.length);
        const combined = await aesEncrypt(payload.buffer, pass, iters);
        const baseDefault = f.name.replace(/\.[^\.]+$/, '');
        let base = prompt('Enter base name for encrypted file (no extension)', baseDefault);
        if (base === null) {
            showToast('Cancelled', 'info');
            return;
        }
        base = base.replace(/\.[^\.]+$/, '');
        const outName = base + '.enc';
        const blob = new Blob([combined], { type: 'application/octet-stream' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = outName;
        a.click();
        showToast('Saved ' + outName, 'success');
    } catch (e) {
        showToast('Encrypt failed: ' + e.message, 'error');
    }
}

async function decryptFile() {
    const f = fileInput.files[0];
    if (!f) {
        showToast('Select a file', 'warning');
        return;
    }
    const pass = passEl.value;
    if (!pass) {
        showToast('Enter passphrase', 'warning');
        return;
    }
    const iters = Math.max(1000, Number(itersEl.value) || 150000);
    try {
        const combinedBuf = await f.arrayBuffer();
        const payloadBuf = await aesDecrypt(combinedBuf, pass, iters);
        const payload = new Uint8Array(payloadBuf);
        if (payload.length < 4) {
            showToast('Invalid payload', 'error');
            return;
        }
        const metaLen = readUint32BE(payload, 0);
        const metaStart = 4;
        const metaEnd = 4 + metaLen;
        if (metaEnd > payload.length) {
            showToast('Invalid metadata length', 'error');
            return;
        }
        const metaBytes = payload.slice(metaStart, metaEnd);
        const metaStr = new TextDecoder().decode(metaBytes);
        let meta;
        try {
            meta = JSON.parse(metaStr);
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
        if (base === null) {
            showToast('Cancelled', 'info');
            return;
        }
        base = base.replace(/\.[^\.]+$/, '');
        const outName = base + ext;
        const blob = new Blob([fileBytes], { type: 'application/octet-stream' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = outName;
        a.click();
        showToast('Saved ' + outName, 'success');
    } catch (e) {
        showToast('Decrypt failed: ' + e.message, 'error');
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
        if (!text) {
            showToast('Clipboard empty', 'warning');
            return;
        }
        plainEl.value = text;
        showToast('Pasted from clipboard', 'info');
    } catch (e) {
        showToast('Paste failed: ' + e.message, 'error');
    }
});

// Clear Input button (keeps passphrase)
document.getElementById('clearInput').addEventListener('click', () => {
    plainEl.value = '';
    outEl.value = '';
    showToast('Input cleared', 'info');
});
