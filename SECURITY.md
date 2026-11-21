# Khazna (خزنة) — Security Architecture & Cryptographic Specification

This document specifies the cryptographic design, storage model, authentication mechanisms, and honest platform boundaries of **Khazna (خزنة)**.

---

## 1. Cryptographic Primitives & Key Hierarchy

All cryptographic operations run 100% locally in the browser using WebCrypto (`crypto.subtle`), `crypto.getRandomValues` (never `Math.random`), and a built-in pure-JS RFC 9106 Argon2id implementation executed inside a dedicated Web Worker (`src/crypto/kdf-worker.js`).

### 1.1 Data Encryption Key (DEK)
- Generated once per vault using `crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])` only for initial wrapping, then immediately re-imported as a **non-extractable** `CryptoKey` (`extractable: false`) stored inside a private JS class field (`VaultSession.#dek`) — never attached to `window`, `globalThis`, `localStorage`, or IndexedDB.
- On lock, `#dek` is dropped, plaintext record caches are cleared, and working `Uint8Array` buffers are overwritten with zeros (best effort).
- Changing the Master Password or rotating the Recovery Key re-wraps the existing DEK atomically without re-encrypting every record.

### 1.2 Independent DEK Wrappers
The vault header (`vault_meta.header`) stores `{ schemaVersion, vaultId, kdf, kdfParams, wrappers }` where any independent wrapper can unwrap the DEK:

1. **Master Password Wrapper (`wrappers.master`)**:
   - Policy: minimum 12 characters, strength meter, confirmation field, no password hint stored.
   - Primary KDF: **Argon2id (RFC 9106)**, memory `>= 32 MiB` (`32768 KiB`), iterations `>= 3`, parallelism `1`, calibrated on the user's device to ~1 second (capped to stay responsive), with 16-byte random salt.
   - Optional local WASM hook: if a locally vendored `vendor/argon2.esm.js` is present, Khazna uses it first; otherwise it uses the built-in RFC 9106 pure-JS Argon2id (verified byte-for-byte against RFC 9106 §5.3 test vector in `tests/crypto-storage.test.mjs`).
   - Fallback KDF (only if Argon2id fails/is unavailable): **PBKDF2-HMAC-SHA-256** with `>= 600,000` iterations.
   - Derived 256-bit KEK wraps the raw 32-bit-aligned 256-bit DEK with AES-256-GCM using a fresh 96-bit IV and AAD `khazna:v1:wrap:master:<vaultId>`.

2. **One-Time Recovery Key Wrapper (`wrappers.recovery`)**:
   - 256-bit random entropy + 24-bit SHA-256 checksum = 280 bits encoded as 56 RFC 4648 Base32 characters (`14 groups of 4`: `XXXX-XXXX-...`).
   - Key derivation: `HKDF-SHA-256(ikm = recoveryEntropy, salt = randomSalt16, info = "khazna:v1:recovery-kek:<vaultId>")` -> 256-bit AES-GCM wrapping key.
   - Shown once on creation (and on explicit rotation) with mandatory "I saved it" confirmation.

3. **Biometric Wrapper (`wrappers.biometric`)**:
   - **Preferred Mode (`prf`)**: Uses WebAuthn Platform Authenticator (`authenticatorAttachment: 'platform'`, `userVerification: 'required'`) with the `prf` extension (`eval.first = random 32-byte salt`). Handles Android authenticators that only return PRF results on `navigator.credentials.get()` rather than `create()`. The 32-byte PRF output is fed into `HKDF-SHA-256` to derive an AES-256-GCM wrapping key that cryptographically wraps the DEK.
   - **Honest Convenience Fallback (`convenience`)**: Only offered after an explicit warning if the browser/authenticator lacks PRF support. Stores the wrapped DEK **in volatile RAM only** (never persisted to disk), gated by a real WebAuthn platform assertion whose **COSE ECDSA P-256 or RS256 signature is cryptographically verified via WebCrypto** against the enrolled public key + monotonic signCount check. Strictly requires the Master Password on every cold start and every 24 hours, and can be disabled at any time.

### 1.3 Record Encryption (AES-256-GCM + AAD)
Every sensitive record (`password`, `card`, `note`, `section`, `draft`) is serialized to JSON and encrypted with:
- Algorithm: **AES-256-GCM** (128-bit auth tag).
- IV: Fresh random **96-bit (12-byte)** IV per write from `crypto.getRandomValues`.
- AAD: Canonical UTF-8 string `khazna:v1|vault=<vaultId>|type=<type>|id=<id>|sv=<schemaVersion>`.
  Modifying the ciphertext, IV, record ID, record type, or vault ID causes authentication failure on decryption.
- Plaintext UI preferences (language, theme, auto-lock timeout, clipboard delay) are strictly non-secret.

---

## 2. Lock, Brute-Force Protection & Cross-Tab Concurrency

- **Exponential Back-Off**: Persisted failed-attempt counter enforces exponential delays (`1s, 2s, 4s, 8s, 16s, 30s, 60s, 120s, 300s`).
- **Optional Wipe-After-N-Failures**: Off by default; requires explicit opt-in with warning. Wipes IndexedDB vault data after `N` consecutive failures.
- **Auto-Lock & Privacy Overlay**: Locks on manual trigger, configurable inactivity timeout (`30s–15m`), or background grace period. Immediately applies a blur/shield overlay on `visibilitychange` / `blur`.
- **Web Locks + BroadcastChannel**: All IndexedDB writes acquire an exclusive `navigator.locks.request('khazna-vault-write', ...)` lock so two tabs can never interleave mutations. Locking or updating vault state broadcasts a notification across tabs via `BroadcastChannel('khazna-sync')`.

---

## 3. Content Security Policy & HTTP Headers

Both `index.html` (`<meta http-equiv="Content-Security-Policy">`) and `_headers` enforce:

```text
default-src 'none';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
manifest-src 'self';
worker-src 'self';
base-uri 'none';
form-action 'none'
```

- Zero inline `<script>`, zero inline `style="..."`, zero `eval`/`new Function`, zero `innerHTML` anywhere in `src/`.
- Additional `_headers` hardening: `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, restrictive `Permissions-Policy`.
- **User-Gated Updates**: `sw.js` never calls `skipWaiting()` automatically. Updates wait until the user confirms installation. Settings displays the current version and SHA-256 hash of the app shell (`app-integrity.json`).

---

## 4. Import / Export Security

- **`.vault` Encrypted Export**: Independent export salt + Argon2id/PBKDF2 key derivation + AES-256-GCM with AAD `khazna:export:v1`.
- **Plain Exports (CSV / Plain JSON / `.spass`)**: Require explicit re-authentication (when enabled) and display a clear red warning before exporting unencrypted data.
- **`.spass` Samsung Pass Format**: AES-256-CBC + PBKDF2-HMAC-SHA-256 (70,000 iterations, 20-byte salt, 16-byte IV) with tolerant Base64/semicolon parsing. Because Samsung does not publish a formal specification, `.spass` export is explicitly labeled best-effort.
- **Atomic Import & Rollback**: Every import saves an encrypted rolling snapshot before writing so the user can restore the prior state cleanly.

---

## 5. Honest Threat Model & Platform Limitations

| Area | What Khazna Does | Platform Limitation (Honest Disclosure) |
|---|---|---|
| **Screenshots / Screen Capture** | Applies a blur overlay on `blur` and `visibilitychange` (app switcher). | Web apps / PWAs cannot set Android's `FLAG_SECURE`; screenshots and screen recorders cannot be blocked by JavaScript. |
| **Clipboard Auto-Clear** | Attempts to overwrite the clipboard after the configured delay (default 30s). | Browsers often block clipboard writes while backgrounded, and OS keyboard clipboard histories (Gboard / Samsung Keyboard) cannot be erased by web apps. |
| **Memory Zeroing** | Overwrites `Uint8Array` buffers with `0` and drops references on lock; DEK is non-extractable. | JavaScript strings are immutable and GC timing is controlled by the browser engine; hardware-level RAM scrubbing is not guaranteed. |
| **Device Compromise** | Protects data at rest against offline disk/backup inspection and casual access. | Cannot defend against a rooted/malware-infected OS, compromised browser binary, or keylogger running on the device. |
| **Static Host Trust** | Zero server telemetry or data uploads; SW updates require explicit user confirmation; app-shell SHA-256 is displayed. | Like all web apps, if the static hosting origin is compromised *before* first load or during a confirmed update, malicious JS could be served. |
