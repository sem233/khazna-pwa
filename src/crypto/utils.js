/**
 * Khazna Cryptographic Utilities
 * Strictly uses WebCrypto CSPRNG (crypto.getRandomValues). Never uses Math.random().
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

// Ambiguity-free 32-character alphabet (no 0/O, no 1/I) for manual paper backup of Recovery Keys.
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const RECOVERY_LOOKUP = new Map(
  Array.from(RECOVERY_ALPHABET, (ch, idx) => [ch, idx])
);

/**
 * Structured application error with bilingual (Arabic/English) user-safe messages.
 */
export class KhaznaError extends Error {
  /**
   * @param {string} code
   * @param {string} ar
   * @param {string} en
   * @param {unknown} [cause]
   */
  constructor(code, ar, en, cause) {
    super(en, cause !== undefined ? { cause } : undefined);
    this.name = 'KhaznaError';
    this.code = code;
    this.ar = ar;
    this.en = en;
  }
}

/**
 * Returns cryptographically strong random bytes.
 * @param {number} length
 * @returns {Uint8Array}
 */
export function randomBytes(length) {
  if (!Number.isInteger(length) || length < 0 || length > 65536) {
    throw new KhaznaError(
      'INVALID_RANDOM_LENGTH',
      'طول البيانات العشوائية غير صالح.',
      'Invalid random byte length.'
    );
  }
  const buf = new Uint8Array(length);
  if (length > 0) {
    globalThis.crypto.getRandomValues(buf);
  }
  return buf;
}

/**
 * Unbiased CSPRNG integer in [0, max) using rejection sampling.
 * @param {number} max Exclusive upper bound (1 <= max <= 2^32).
 * @returns {number}
 */
export function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 0x100000000) {
    throw new KhaznaError(
      'INVALID_RANGE',
      'نطاق الرقم العشوائي غير صالح.',
      'Invalid random integer upper bound.'
    );
  }
  if (max === 1) return 0;
  const range = 0x100000000;
  const limit = Math.floor(range / max) * max;
  const buf = new Uint32Array(1);
  let value;
  do {
    globalThis.crypto.getRandomValues(buf);
    value = buf[0];
  } while (value >= limit);
  buf[0] = 0;
  return value % max;
}

/**
 * Generates a 128-bit URL-safe random identifier.
 * @param {string} [prefix]
 * @returns {string}
 */
export function randomId(prefix = '') {
  const bytes = randomBytes(16);
  const id = bytesToBase64Url(bytes);
  return prefix ? `${prefix}_${id}` : id;
}

/**
 * Best-effort buffer zeroing.
 * Note: JavaScript runtimes cannot guarantee that GC copies or immutable strings are wiped.
 * @param {...(ArrayBufferView|ArrayBuffer|null|undefined)} buffers
 */
export function zeroize(...buffers) {
  for (const buf of buffers) {
    if (!buf) continue;
    try {
      if (buf instanceof ArrayBuffer) {
        if (buf.detached || buf.byteLength === 0) continue;
        new Uint8Array(buf).fill(0);
      } else if (ArrayBuffer.isView(buf)) {
        if (!buf.buffer || buf.buffer.detached || buf.byteLength === 0) continue;
        new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).fill(0);
      }
    } catch {
      // Buffer may already have been transferred/detached (e.g. postMessage to Web Worker)
    }
  }
}

/**
 * Constant-time byte array equality check.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * @param {string} str
 * @returns {Uint8Array}
 */
export function utf8Encode(str) {
  return textEncoder.encode(str);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function utf8Decode(bytes) {
  return textDecoder.decode(bytes);
}

/**
 * Chunked Base64 encoder safe for arbitrarily large Uint8Arrays (no call-stack overflow).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64(bytes) {
  const chunkSize = 0x8000;
  const parts = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    parts.push(String.fromCharCode.apply(null, slice));
  }
  return btoa(parts.join(''));
}

/**
 * Base64 decoder accepting standard or whitespace-wrapped Base64.
 * @param {string} b64
 * @returns {Uint8Array}
 */
export function base64ToBytes(b64) {
  const clean = String(b64).replace(/\s+/g, '');
  let binary;
  try {
    binary = atob(clean);
  } catch (err) {
    throw new KhaznaError(
      'INVALID_BASE64',
      'البيانات المشفّرة (Base64) تالفة أو غير صالحة.',
      'Invalid Base64 encoding.',
      err
    );
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * @param {string} b64url
 * @returns {Uint8Array}
 */
export function base64UrlToBytes(b64url) {
  let str = String(b64url).replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4 !== 0) str += '=';
  return base64ToBytes(str);
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  const clean = String(hex).trim();
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new KhaznaError('INVALID_HEX', 'سلسلة سداسية غير صالحة.', 'Invalid hex string.');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Computes SHA-256 digest using WebCrypto.
 * @param {Uint8Array|string} input
 * @returns {Promise<Uint8Array>}
 */
export async function sha256Bytes(input) {
  const data = typeof input === 'string' ? utf8Encode(input) : input;
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

/**
 * Computes lowercase hex SHA-256 digest.
 * @param {Uint8Array|string} input
 * @returns {Promise<string>}
 */
export async function sha256Hex(input) {
  return bytesToHex(await sha256Bytes(input));
}

/**
 * Encodes a 32-byte (256-bit) recovery key with a 3-byte (24-bit) SHA-256 checksum
 * into 56 Base32 characters grouped into 14 blocks of 4: XXXX-XXXX-...
 * @param {Uint8Array} keyBytes
 * @returns {Promise<string>}
 */
export async function encodeRecoveryKey(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new KhaznaError(
      'INVALID_RECOVERY_KEY_LEN',
      'يجب أن يكون مفتاح الاسترداد بطول ٢٥٦ بت (٣٢ بايت).',
      'Recovery key must be exactly 32 bytes (256 bits).'
    );
  }
  const hash = await sha256Bytes(keyBytes);
  const payload = new Uint8Array(35);
  payload.set(keyBytes, 0);
  payload.set(hash.subarray(0, 3), 32);

  let chars = '';
  let bitBuffer = 0;
  let bitCount = 0;
  for (let i = 0; i < payload.length; i++) {
    bitBuffer = (bitBuffer << 8) | payload[i];
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      chars += RECOVERY_ALPHABET[(bitBuffer >>> bitCount) & 0x1f];
    }
  }
  zeroize(payload, hash);

  const groups = [];
  for (let i = 0; i < chars.length; i += 4) {
    groups.push(chars.slice(i, i + 4));
  }
  return groups.join('-');
}

/**
 * Decodes and checksum-verifies a grouped Base32 recovery key.
 * @param {string} formatted
 * @returns {Promise<Uint8Array>} 32-byte recovery key
 */
export async function decodeRecoveryKey(formatted) {
  const clean = String(formatted || '')
    .toUpperCase()
    .replace(/[\s\-_]+/g, '');

  if (clean.length !== 56) {
    throw new KhaznaError(
      'INVALID_RECOVERY_KEY',
      'مفتاح الاسترداد غير مكتمل أو طوله غير صحيح (المطلوب ١٤ مجموعة من ٤ أحرف).',
      'Recovery key length is invalid (expected 14 groups of 4 characters).'
    );
  }

  const payload = new Uint8Array(35);
  let bitBuffer = 0;
  let bitCount = 0;
  let outIdx = 0;

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    const val = RECOVERY_LOOKUP.get(ch);
    if (val === undefined) {
      throw new KhaznaError(
        'INVALID_RECOVERY_KEY',
        `مفتاح الاسترداد يحتوي على حرف غير مسموح (${ch}). تأكد من عدم الخلط بين 0/O أو 1/I.`,
        `Recovery key contains invalid character "${ch}".`
      );
    }
    bitBuffer = (bitBuffer << 5) | val;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      payload[outIdx++] = (bitBuffer >>> bitCount) & 0xff;
    }
  }

  const keyBytes = payload.slice(0, 32);
  const embeddedChecksum = payload.slice(32, 35);
  const expectedHash = await sha256Bytes(keyBytes);
  const valid = constantTimeEqual(embeddedChecksum, expectedHash.subarray(0, 3));

  zeroize(payload, embeddedChecksum, expectedHash);

  if (!valid) {
    zeroize(keyBytes);
    throw new KhaznaError(
      'INVALID_RECOVERY_KEY_CHECKSUM',
      'فشل التحقق من صحة مفتاح الاسترداد — يُرجى مراجعة الأحرف بحثاً عن خطأ إملائي.',
      'Recovery key checksum mismatch — please check for typos.'
    );
  }

  return keyBytes;
}

/**
 * Builds canonical Additional Authenticated Data (AAD) binding ciphertext to its metadata.
 * Any alteration to id, type, schemaVersion, or vaultId invalidates AES-GCM decryption.
 * @param {{ id: string, type: string, schemaVersion: number, vaultId: string }} meta
 * @returns {Uint8Array}
 */
export function buildAAD({ id, type, schemaVersion, vaultId }) {
  if (
    typeof id !== 'string' || !id ||
    typeof type !== 'string' || !type ||
    !Number.isInteger(schemaVersion) || schemaVersion < 1 ||
    typeof vaultId !== 'string' || !vaultId
  ) {
    throw new KhaznaError(
      'INVALID_AAD',
      'بيانات التحقق المرتبطة بالتشفير (AAD) غير صالحة.',
      'Invalid AAD binding fields.'
    );
  }
  const canonical = JSON.stringify({
    id,
    schemaVersion,
    type,
    vaultId,
  });
  return utf8Encode(canonical);
}

/**
 * Concatenates multiple Uint8Arrays into a single Uint8Array.
 * @param {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
