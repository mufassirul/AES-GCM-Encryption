# AES-256 Bit Encryptor (AES-GCM Mode)

A fast, secure, and fully offline AES-256 encryption/decryption tool for **text** and **files**, built with WebCrypto API.  
Uses random IVs, authentication tags, and password-based key derivation (PBKDF2 + SHA-256).

## 🔐 Features
- AES-256 GCM encryption (authenticated)
- Random 12-byte IV and 16-byte salt per encryption
- Auth tag automatically included
- Text and file encryption/decryption
- Password-based key derivation using PBKDF2 (SHA-256)
- Adjustable iteration count (default 200,000)
- Works fully offline — no data leaves your device
- Supports `.aes` (text) and `.enc` (file) formats for visual clarity

## ⚙️ How It Works
- Each encryption uses:
  - 16-byte random **salt**
  - 12-byte random **IV**
  - 128-bit authentication tag (built-in by AES-GCM)
- The final encrypted output = `[salt][iv][ciphertext+tag]`
- Password → PBKDF2 (SHA-256, 150,000+ iterations) → AES-GCM key

## 📄 Usage
### 🔸 Text Encryption / Decryption
1. Enter text and passphrase.
2. Click **Encrypt Text** → output appears in `.aes` format.
3. Copy or download result (saved as `yourname.aes`).
4. To decrypt: paste `.aes` text, enter the same passphrase, and click **Decrypt Text**.

### 🔸 File Encryption / Decryption
1. Choose a file.
2. Enter your passphrase.
3. Click **Encrypt File** → saves as `filename.enc`.
4. To decrypt, upload the `.enc` file and enter the same passphrase.

### 🔸 File Extensions
- `.aes` → text-based encrypted data  
- `.enc` → file-based encrypted data  
*(Purely visual; both are AES-GCM encrypted content.)*

## 💡 Notes
- Minimum PBKDF2 iterations: **1000** (recommended 150,000+)
- All crypto operations use `window.crypto.subtle` (no external libs)
- No network requests or data uploads — 100% local in browser
- Works on desktop and mobile browsers

## 🧠 Security Tips
- Use long, unique passphrases (12+ random characters)
- Never reuse passphrases across different files
- Keep your `.aes` / `.enc` files safe; losing your passphrase means data is unrecoverable

---

### 🛠️ Built With
- HTML, CSS, JavaScript (Vanilla)
- WebCrypto API (`AES-GCM`, `PBKDF2`)