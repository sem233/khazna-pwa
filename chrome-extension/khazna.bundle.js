(() => {
  // src/crypto/utils.js
  var textEncoder = new TextEncoder();
  var textDecoder = new TextDecoder("utf-8", { fatal: true });
  var RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  var RECOVERY_LOOKUP = new Map(
    Array.from(RECOVERY_ALPHABET, (ch, idx) => [ch, idx])
  );
  var KhaznaError = class extends Error {
    /**
     * @param {string} code
     * @param {string} ar
     * @param {string} en
     * @param {unknown} [cause]
     */
    constructor(code, ar, en, cause) {
      super(en, cause !== void 0 ? { cause } : void 0);
      this.name = "KhaznaError";
      this.code = code;
      this.ar = ar;
      this.en = en;
    }
  };
  function randomBytes(length) {
    if (!Number.isInteger(length) || length < 0 || length > 65536) {
      throw new KhaznaError(
        "INVALID_RANDOM_LENGTH",
        "\u0637\u0648\u0644 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0639\u0634\u0648\u0627\u0626\u064A\u0629 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D.",
        "Invalid random byte length."
      );
    }
    const buf = new Uint8Array(length);
    if (length > 0) {
      globalThis.crypto.getRandomValues(buf);
    }
    return buf;
  }
  function randomInt(max) {
    if (!Number.isInteger(max) || max <= 0 || max > 4294967296) {
      throw new KhaznaError(
        "INVALID_RANGE",
        "\u0646\u0637\u0627\u0642 \u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u0639\u0634\u0648\u0627\u0626\u064A \u063A\u064A\u0631 \u0635\u0627\u0644\u062D.",
        "Invalid random integer upper bound."
      );
    }
    if (max === 1) return 0;
    const range = 4294967296;
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
  function randomId(prefix = "") {
    const bytes = randomBytes(16);
    const id = bytesToBase64Url(bytes);
    return prefix ? `${prefix}_${id}` : id;
  }
  function zeroize(...buffers) {
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
      }
    }
  }
  function constantTimeEqual(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }
  function utf8Encode(str) {
    return textEncoder.encode(str);
  }
  function utf8Decode(bytes) {
    return textDecoder.decode(bytes);
  }
  function bytesToBase64(bytes) {
    const chunkSize = 32768;
    const parts = [];
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const slice = bytes.subarray(i, i + chunkSize);
      parts.push(String.fromCharCode.apply(null, slice));
    }
    return btoa(parts.join(""));
  }
  function base64ToBytes(b64) {
    const clean = String(b64).replace(/\s+/g, "");
    let binary;
    try {
      binary = atob(clean);
    } catch (err) {
      throw new KhaznaError(
        "INVALID_BASE64",
        "\u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u0634\u0641\u0651\u0631\u0629 (Base64) \u062A\u0627\u0644\u0641\u0629 \u0623\u0648 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D\u0629.",
        "Invalid Base64 encoding.",
        err
      );
    }
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }
  function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function base64UrlToBytes(b64url) {
    let str = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4 !== 0) str += "=";
    return base64ToBytes(str);
  }
  function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }
  async function sha256Bytes(input) {
    const data = typeof input === "string" ? utf8Encode(input) : input;
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(digest);
  }
  async function sha256Hex(input) {
    return bytesToHex(await sha256Bytes(input));
  }
  async function encodeRecoveryKey(keyBytes) {
    if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
      throw new KhaznaError(
        "INVALID_RECOVERY_KEY_LEN",
        "\u064A\u062C\u0628 \u0623\u0646 \u064A\u0643\u0648\u0646 \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0628\u0637\u0648\u0644 \u0662\u0665\u0666 \u0628\u062A (\u0663\u0662 \u0628\u0627\u064A\u062A).",
        "Recovery key must be exactly 32 bytes (256 bits)."
      );
    }
    const hash = await sha256Bytes(keyBytes);
    const payload = new Uint8Array(35);
    payload.set(keyBytes, 0);
    payload.set(hash.subarray(0, 3), 32);
    let chars = "";
    let bitBuffer = 0;
    let bitCount = 0;
    for (let i = 0; i < payload.length; i++) {
      bitBuffer = bitBuffer << 8 | payload[i];
      bitCount += 8;
      while (bitCount >= 5) {
        bitCount -= 5;
        chars += RECOVERY_ALPHABET[bitBuffer >>> bitCount & 31];
      }
    }
    zeroize(payload, hash);
    const groups = [];
    for (let i = 0; i < chars.length; i += 4) {
      groups.push(chars.slice(i, i + 4));
    }
    return groups.join("-");
  }
  async function decodeRecoveryKey(formatted) {
    const clean = String(formatted || "").toUpperCase().replace(/[\s\-_]+/g, "");
    if (clean.length !== 56) {
      throw new KhaznaError(
        "INVALID_RECOVERY_KEY",
        "\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u063A\u064A\u0631 \u0645\u0643\u062A\u0645\u0644 \u0623\u0648 \u0637\u0648\u0644\u0647 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D (\u0627\u0644\u0645\u0637\u0644\u0648\u0628 \u0661\u0664 \u0645\u062C\u0645\u0648\u0639\u0629 \u0645\u0646 \u0664 \u0623\u062D\u0631\u0641).",
        "Recovery key length is invalid (expected 14 groups of 4 characters)."
      );
    }
    const payload = new Uint8Array(35);
    let bitBuffer = 0;
    let bitCount = 0;
    let outIdx = 0;
    for (let i = 0; i < clean.length; i++) {
      const ch = clean[i];
      const val = RECOVERY_LOOKUP.get(ch);
      if (val === void 0) {
        throw new KhaznaError(
          "INVALID_RECOVERY_KEY",
          `\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u064A\u062D\u062A\u0648\u064A \u0639\u0644\u0649 \u062D\u0631\u0641 \u063A\u064A\u0631 \u0645\u0633\u0645\u0648\u062D (${ch}). \u062A\u0623\u0643\u062F \u0645\u0646 \u0639\u062F\u0645 \u0627\u0644\u062E\u0644\u0637 \u0628\u064A\u0646 0/O \u0623\u0648 1/I.`,
          `Recovery key contains invalid character "${ch}".`
        );
      }
      bitBuffer = bitBuffer << 5 | val;
      bitCount += 5;
      if (bitCount >= 8) {
        bitCount -= 8;
        payload[outIdx++] = bitBuffer >>> bitCount & 255;
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
        "INVALID_RECOVERY_KEY_CHECKSUM",
        "\u0641\u0634\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0635\u062D\u0629 \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u2014 \u064A\u064F\u0631\u062C\u0649 \u0645\u0631\u0627\u062C\u0639\u0629 \u0627\u0644\u0623\u062D\u0631\u0641 \u0628\u062D\u062B\u0627\u064B \u0639\u0646 \u062E\u0637\u0623 \u0625\u0645\u0644\u0627\u0626\u064A.",
        "Recovery key checksum mismatch \u2014 please check for typos."
      );
    }
    return keyBytes;
  }
  function buildAAD({ id, type, schemaVersion, vaultId }) {
    if (typeof id !== "string" || !id || typeof type !== "string" || !type || !Number.isInteger(schemaVersion) || schemaVersion < 1 || typeof vaultId !== "string" || !vaultId) {
      throw new KhaznaError(
        "INVALID_AAD",
        "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u062A\u062D\u0642\u0642 \u0627\u0644\u0645\u0631\u062A\u0628\u0637\u0629 \u0628\u0627\u0644\u062A\u0634\u0641\u064A\u0631 (AAD) \u063A\u064A\u0631 \u0635\u0627\u0644\u062D\u0629.",
        "Invalid AAD binding fields."
      );
    }
    const canonical = JSON.stringify({
      id,
      schemaVersion,
      type,
      vaultId
    });
    return utf8Encode(canonical);
  }
  function concatBytes(...arrays) {
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

  // src/crypto/argon2id-pure.js
  var BLAKE2B_IV_LO = new Uint32Array([
    4089235720,
    2227873595,
    4271175723,
    1595750129,
    2917565137,
    725511199,
    4215389547,
    327033209
  ]);
  var BLAKE2B_IV_HI = new Uint32Array([
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
  ]);
  var SIGMA = new Uint8Array([
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9,
    12,
    5,
    1,
    15,
    14,
    13,
    4,
    10,
    0,
    7,
    6,
    3,
    9,
    2,
    8,
    11,
    13,
    11,
    7,
    14,
    12,
    1,
    3,
    9,
    5,
    0,
    15,
    4,
    8,
    6,
    2,
    10,
    6,
    15,
    14,
    9,
    11,
    3,
    0,
    8,
    12,
    2,
    13,
    7,
    1,
    4,
    10,
    5,
    10,
    2,
    8,
    4,
    7,
    6,
    1,
    5,
    15,
    11,
    9,
    14,
    3,
    12,
    13,
    0,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3
  ]);
  var b2vLo = new Uint32Array(16);
  var b2vHi = new Uint32Array(16);
  var b2mLo = new Uint32Array(16);
  var b2mHi = new Uint32Array(16);
  function b2G(a, b, c, d, ix, iy) {
    let aLo = b2vLo[a], aHi = b2vHi[a];
    let bLo = b2vLo[b], bHi = b2vHi[b];
    let cLo = b2vLo[c], cHi = b2vHi[c];
    let dLo = b2vLo[d], dHi = b2vHi[d];
    let s1 = aLo + bLo >>> 0;
    let carry = s1 < aLo ? 1 : 0;
    let s2 = s1 + b2mLo[ix] >>> 0;
    carry += s2 < s1 ? 1 : 0;
    aHi = aHi + bHi + b2mHi[ix] + carry >>> 0;
    aLo = s2;
    let xLo = (dLo ^ aLo) >>> 0;
    let xHi = (dHi ^ aHi) >>> 0;
    dLo = xHi;
    dHi = xLo;
    s1 = cLo + dLo >>> 0;
    cHi = cHi + dHi + (s1 < cLo ? 1 : 0) >>> 0;
    cLo = s1;
    xLo = (bLo ^ cLo) >>> 0;
    xHi = (bHi ^ cHi) >>> 0;
    bLo = (xLo >>> 24 | xHi << 8) >>> 0;
    bHi = (xHi >>> 24 | xLo << 8) >>> 0;
    s1 = aLo + bLo >>> 0;
    carry = s1 < aLo ? 1 : 0;
    s2 = s1 + b2mLo[iy] >>> 0;
    carry += s2 < s1 ? 1 : 0;
    aHi = aHi + bHi + b2mHi[iy] + carry >>> 0;
    aLo = s2;
    xLo = (dLo ^ aLo) >>> 0;
    xHi = (dHi ^ aHi) >>> 0;
    dLo = (xLo >>> 16 | xHi << 16) >>> 0;
    dHi = (xHi >>> 16 | xLo << 16) >>> 0;
    s1 = cLo + dLo >>> 0;
    cHi = cHi + dHi + (s1 < cLo ? 1 : 0) >>> 0;
    cLo = s1;
    xLo = (bLo ^ cLo) >>> 0;
    xHi = (bHi ^ cHi) >>> 0;
    bLo = (xLo << 1 | xHi >>> 31) >>> 0;
    bHi = (xHi << 1 | xLo >>> 31) >>> 0;
    b2vLo[a] = aLo;
    b2vHi[a] = aHi;
    b2vLo[b] = bLo;
    b2vHi[b] = bHi;
    b2vLo[c] = cLo;
    b2vHi[c] = cHi;
    b2vLo[d] = dLo;
    b2vHi[d] = dHi;
  }
  function blake2bCompress(hLo, hHi, block, tLo, tHi, isLast) {
    for (let i = 0; i < 8; i++) {
      b2vLo[i] = hLo[i];
      b2vHi[i] = hHi[i];
      b2vLo[i + 8] = BLAKE2B_IV_LO[i];
      b2vHi[i + 8] = BLAKE2B_IV_HI[i];
    }
    b2vLo[12] ^= tLo;
    b2vHi[12] ^= tHi;
    if (isLast) {
      b2vLo[14] = ~b2vLo[14] >>> 0;
      b2vHi[14] = ~b2vHi[14] >>> 0;
    }
    for (let i = 0; i < 16; i++) {
      const o = i * 8;
      b2mLo[i] = (block[o] | block[o + 1] << 8 | block[o + 2] << 16 | block[o + 3] << 24) >>> 0;
      b2mHi[i] = (block[o + 4] | block[o + 5] << 8 | block[o + 6] << 16 | block[o + 7] << 24) >>> 0;
    }
    for (let r = 0; r < 12; r++) {
      const s = r * 16;
      b2G(0, 4, 8, 12, SIGMA[s], SIGMA[s + 1]);
      b2G(1, 5, 9, 13, SIGMA[s + 2], SIGMA[s + 3]);
      b2G(2, 6, 10, 14, SIGMA[s + 4], SIGMA[s + 5]);
      b2G(3, 7, 11, 15, SIGMA[s + 6], SIGMA[s + 7]);
      b2G(0, 5, 10, 15, SIGMA[s + 8], SIGMA[s + 9]);
      b2G(1, 6, 11, 12, SIGMA[s + 10], SIGMA[s + 11]);
      b2G(2, 7, 8, 13, SIGMA[s + 12], SIGMA[s + 13]);
      b2G(3, 4, 9, 14, SIGMA[s + 14], SIGMA[s + 15]);
    }
    for (let i = 0; i < 8; i++) {
      hLo[i] = (hLo[i] ^ b2vLo[i] ^ b2vLo[i + 8]) >>> 0;
      hHi[i] = (hHi[i] ^ b2vHi[i] ^ b2vHi[i + 8]) >>> 0;
    }
  }
  function blake2b(data, outLen = 64) {
    if (outLen < 1 || outLen > 64) {
      throw new RangeError("BLAKE2b output length must be 1..64 bytes");
    }
    const hLo = new Uint32Array(BLAKE2B_IV_LO);
    const hHi = new Uint32Array(BLAKE2B_IV_HI);
    hLo[0] = (hLo[0] ^ (16842752 | outLen)) >>> 0;
    const block = new Uint8Array(128);
    let tLo = 0;
    let tHi = 0;
    let pos = 0;
    const len = data.length;
    while (len - pos > 128) {
      block.set(data.subarray(pos, pos + 128), 0);
      pos += 128;
      const nextLo2 = tLo + 128 >>> 0;
      if (nextLo2 < tLo) tHi = tHi + 1 >>> 0;
      tLo = nextLo2;
      blake2bCompress(hLo, hHi, block, tLo, tHi, false);
    }
    block.fill(0);
    const rem = len - pos;
    if (rem > 0) {
      block.set(data.subarray(pos, len), 0);
    }
    const nextLo = tLo + rem >>> 0;
    if (nextLo < tLo) tHi = tHi + 1 >>> 0;
    tLo = nextLo;
    blake2bCompress(hLo, hHi, block, tLo, tHi, true);
    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) {
      const wordIdx = i >>> 3;
      const byteInWord = i & 7;
      const word = byteInWord < 4 ? hLo[wordIdx] : hHi[wordIdx];
      out[i] = word >>> (byteInWord & 3) * 8 & 255;
    }
    zeroize(hLo, hHi, block, b2vLo, b2vHi, b2mLo, b2mHi);
    return out;
  }
  function blake2bLong(input, outLen) {
    const prefixed = new Uint8Array(4 + input.length);
    prefixed[0] = outLen & 255;
    prefixed[1] = outLen >>> 8 & 255;
    prefixed[2] = outLen >>> 16 & 255;
    prefixed[3] = outLen >>> 24 & 255;
    prefixed.set(input, 4);
    if (outLen <= 64) {
      const digest = blake2b(prefixed, outLen);
      zeroize(prefixed);
      return digest;
    }
    const out = new Uint8Array(outLen);
    const r = Math.ceil(outLen / 32) - 2;
    let v = blake2b(prefixed, 64);
    zeroize(prefixed);
    out.set(v.subarray(0, 32), 0);
    for (let i = 2; i <= r; i++) {
      const next = blake2b(v, 64);
      zeroize(v);
      v = next;
      out.set(v.subarray(0, 32), (i - 1) * 32);
    }
    const lastLen = outLen - 32 * r;
    const last = blake2b(v, lastLen);
    zeroize(v);
    out.set(last, r * 32);
    zeroize(last);
    return out;
  }
  var BLOCK_U32 = 256;
  var SYNC_POINTS = 4;
  var ADDRESSES_IN_BLOCK = 128;
  function argon2GB(B, ia, ib, ic, id) {
    const ao = ia << 1, bo = ib << 1, co = ic << 1, do_ = id << 1;
    let aLo = B[ao], aHi = B[ao + 1];
    let bLo = B[bo], bHi = B[bo + 1];
    let cLo = B[co], cHi = B[co + 1];
    let dLo = B[do_], dHi = B[do_ + 1];
    let xl, xh, yl, yh, p0, p1, p2, p3, mid, prodLo, prodHi, mLo, mHi, s1, s2, c1, c2, tLo, tHi;
    xl = aLo & 65535;
    xh = aLo >>> 16;
    yl = bLo & 65535;
    yh = bLo >>> 16;
    p0 = xl * yl;
    p1 = xh * yl;
    p2 = xl * yh;
    p3 = xh * yh;
    mid = (p0 >>> 16) + (p1 & 65535) + (p2 & 65535);
    prodLo = (p0 & 65535 | (mid & 65535) << 16) >>> 0;
    prodHi = p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16) >>> 0;
    mHi = (prodHi << 1 | prodLo >>> 31) >>> 0;
    mLo = prodLo << 1 >>> 0;
    s1 = aLo + bLo >>> 0;
    c1 = s1 < aLo ? 1 : 0;
    s2 = s1 + mLo >>> 0;
    c2 = s2 < s1 ? 1 : 0;
    aHi = aHi + bHi + mHi + c1 + c2 >>> 0;
    aLo = s2;
    tLo = (dLo ^ aLo) >>> 0;
    tHi = (dHi ^ aHi) >>> 0;
    dLo = tHi;
    dHi = tLo;
    xl = cLo & 65535;
    xh = cLo >>> 16;
    yl = dLo & 65535;
    yh = dLo >>> 16;
    p0 = xl * yl;
    p1 = xh * yl;
    p2 = xl * yh;
    p3 = xh * yh;
    mid = (p0 >>> 16) + (p1 & 65535) + (p2 & 65535);
    prodLo = (p0 & 65535 | (mid & 65535) << 16) >>> 0;
    prodHi = p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16) >>> 0;
    mHi = (prodHi << 1 | prodLo >>> 31) >>> 0;
    mLo = prodLo << 1 >>> 0;
    s1 = cLo + dLo >>> 0;
    c1 = s1 < cLo ? 1 : 0;
    s2 = s1 + mLo >>> 0;
    c2 = s2 < s1 ? 1 : 0;
    cHi = cHi + dHi + mHi + c1 + c2 >>> 0;
    cLo = s2;
    tLo = (bLo ^ cLo) >>> 0;
    tHi = (bHi ^ cHi) >>> 0;
    bLo = (tLo >>> 24 | tHi << 8) >>> 0;
    bHi = (tHi >>> 24 | tLo << 8) >>> 0;
    xl = aLo & 65535;
    xh = aLo >>> 16;
    yl = bLo & 65535;
    yh = bLo >>> 16;
    p0 = xl * yl;
    p1 = xh * yl;
    p2 = xl * yh;
    p3 = xh * yh;
    mid = (p0 >>> 16) + (p1 & 65535) + (p2 & 65535);
    prodLo = (p0 & 65535 | (mid & 65535) << 16) >>> 0;
    prodHi = p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16) >>> 0;
    mHi = (prodHi << 1 | prodLo >>> 31) >>> 0;
    mLo = prodLo << 1 >>> 0;
    s1 = aLo + bLo >>> 0;
    c1 = s1 < aLo ? 1 : 0;
    s2 = s1 + mLo >>> 0;
    c2 = s2 < s1 ? 1 : 0;
    aHi = aHi + bHi + mHi + c1 + c2 >>> 0;
    aLo = s2;
    tLo = (dLo ^ aLo) >>> 0;
    tHi = (dHi ^ aHi) >>> 0;
    dLo = (tLo >>> 16 | tHi << 16) >>> 0;
    dHi = (tHi >>> 16 | tLo << 16) >>> 0;
    xl = cLo & 65535;
    xh = cLo >>> 16;
    yl = dLo & 65535;
    yh = dLo >>> 16;
    p0 = xl * yl;
    p1 = xh * yl;
    p2 = xl * yh;
    p3 = xh * yh;
    mid = (p0 >>> 16) + (p1 & 65535) + (p2 & 65535);
    prodLo = (p0 & 65535 | (mid & 65535) << 16) >>> 0;
    prodHi = p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16) >>> 0;
    mHi = (prodHi << 1 | prodLo >>> 31) >>> 0;
    mLo = prodLo << 1 >>> 0;
    s1 = cLo + dLo >>> 0;
    c1 = s1 < cLo ? 1 : 0;
    s2 = s1 + mLo >>> 0;
    c2 = s2 < s1 ? 1 : 0;
    cHi = cHi + dHi + mHi + c1 + c2 >>> 0;
    cLo = s2;
    tLo = (bLo ^ cLo) >>> 0;
    tHi = (bHi ^ cHi) >>> 0;
    bLo = (tLo << 1 | tHi >>> 31) >>> 0;
    bHi = (tHi << 1 | tLo >>> 31) >>> 0;
    B[ao] = aLo;
    B[ao + 1] = aHi;
    B[bo] = bLo;
    B[bo + 1] = bHi;
    B[co] = cLo;
    B[co + 1] = cHi;
    B[do_] = dLo;
    B[do_ + 1] = dHi;
  }
  function blake2RoundNoMsg(B, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) {
    argon2GB(B, v0, v4, v8, v12);
    argon2GB(B, v1, v5, v9, v13);
    argon2GB(B, v2, v6, v10, v14);
    argon2GB(B, v3, v7, v11, v15);
    argon2GB(B, v0, v5, v10, v15);
    argon2GB(B, v1, v6, v11, v12);
    argon2GB(B, v2, v7, v8, v13);
    argon2GB(B, v3, v4, v9, v14);
  }
  function fillBlock(prevBuf, prevOff, refBuf, refOff, nextBuf, nextOff, withXor, blockR, blockTmp) {
    for (let i = 0; i < BLOCK_U32; i++) {
      const r = (prevBuf[prevOff + i] ^ refBuf[refOff + i]) >>> 0;
      blockR[i] = r;
      blockTmp[i] = withXor ? (r ^ nextBuf[nextOff + i]) >>> 0 : r;
    }
    for (let i = 0; i < 8; i++) {
      const b = i * 16;
      blake2RoundNoMsg(
        blockR,
        b,
        b + 1,
        b + 2,
        b + 3,
        b + 4,
        b + 5,
        b + 6,
        b + 7,
        b + 8,
        b + 9,
        b + 10,
        b + 11,
        b + 12,
        b + 13,
        b + 14,
        b + 15
      );
    }
    for (let i = 0; i < 8; i++) {
      const b = i * 2;
      blake2RoundNoMsg(
        blockR,
        b,
        b + 1,
        b + 16,
        b + 17,
        b + 32,
        b + 33,
        b + 48,
        b + 49,
        b + 64,
        b + 65,
        b + 80,
        b + 81,
        b + 96,
        b + 97,
        b + 112,
        b + 113
      );
    }
    for (let i = 0; i < BLOCK_U32; i++) {
      nextBuf[nextOff + i] = (blockTmp[i] ^ blockR[i]) >>> 0;
    }
  }
  function nextAddresses(addrBlock, inputBlock, zeroBlock, blockR, blockTmp) {
    const nextLo = inputBlock[12] + 1 >>> 0;
    if (nextLo === 0) inputBlock[13] = inputBlock[13] + 1 >>> 0;
    inputBlock[12] = nextLo;
    fillBlock(zeroBlock, 0, inputBlock, 0, addrBlock, 0, false, blockR, blockTmp);
    fillBlock(zeroBlock, 0, addrBlock, 0, addrBlock, 0, false, blockR, blockTmp);
  }
  function bytesToBlockU32(bytes, dst, dstOff) {
    for (let i = 0; i < BLOCK_U32; i++) {
      const o = i * 4;
      dst[dstOff + i] = (bytes[o] | bytes[o + 1] << 8 | bytes[o + 2] << 16 | bytes[o + 3] << 24) >>> 0;
    }
  }
  function blockU32ToBytes(src, srcOff) {
    const out = new Uint8Array(1024);
    for (let i = 0; i < BLOCK_U32; i++) {
      const w = src[srcOff + i];
      const o = i * 4;
      out[o] = w & 255;
      out[o + 1] = w >>> 8 & 255;
      out[o + 2] = w >>> 16 & 255;
      out[o + 3] = w >>> 24 & 255;
    }
    return out;
  }
  function writeLE32(buf, offset, val) {
    buf[offset] = val & 255;
    buf[offset + 1] = val >>> 8 & 255;
    buf[offset + 2] = val >>> 16 & 255;
    buf[offset + 3] = val >>> 24 & 255;
  }
  function indexAlpha(pass, slice, index, sameLane, laneLength, segmentLength, j1) {
    let refAreaSize;
    if (pass === 0) {
      if (slice === 0) {
        refAreaSize = index - 1;
      } else if (sameLane) {
        refAreaSize = slice * segmentLength + index - 1;
      } else {
        refAreaSize = slice * segmentLength + (index === 0 ? -1 : 0);
      }
    } else if (sameLane) {
      refAreaSize = laneLength - segmentLength + index - 1;
    } else {
      refAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
    }
    const j1Big = BigInt(j1 >>> 0);
    const x = j1Big * j1Big >> 32n;
    const y = Number(BigInt(refAreaSize) * x >> 32n);
    const relPos = refAreaSize - 1 - y;
    const startPos = pass !== 0 && slice !== SYNC_POINTS - 1 ? (slice + 1) * segmentLength : 0;
    return (startPos + relPos) % laneLength;
  }
  function argon2idPure({
    password,
    salt,
    memorySize,
    iterations,
    parallelism = 1,
    hashLength = 32,
    secret = new Uint8Array(0),
    associatedData = new Uint8Array(0),
    type = 2
  }) {
    if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) {
      throw new TypeError("Argon2id requires Uint8Array password and salt");
    }
    if (!Number.isInteger(parallelism) || parallelism < 1) {
      throw new RangeError("Argon2id parallelism must be >= 1");
    }
    if (!Number.isInteger(iterations) || iterations < 1) {
      throw new RangeError("Argon2id iterations must be >= 1");
    }
    if (!Number.isInteger(hashLength) || hashLength < 4) {
      throw new RangeError("Argon2id hashLength must be >= 4");
    }
    const minMemory = 8 * parallelism;
    if (!Number.isInteger(memorySize) || memorySize < minMemory) {
      throw new RangeError(`Argon2id memorySize must be >= ${minMemory} KiB`);
    }
    const version = 19;
    const memoryBlocks = 4 * parallelism * Math.floor(memorySize / (4 * parallelism));
    const laneLength = memoryBlocks / parallelism;
    const segmentLength = laneLength / SYNC_POINTS;
    const h0InputLen = 40 + password.length + salt.length + secret.length + associatedData.length;
    const h0Input = new Uint8Array(h0InputLen);
    let p = 0;
    writeLE32(h0Input, p, parallelism);
    p += 4;
    writeLE32(h0Input, p, hashLength);
    p += 4;
    writeLE32(h0Input, p, memorySize);
    p += 4;
    writeLE32(h0Input, p, iterations);
    p += 4;
    writeLE32(h0Input, p, version);
    p += 4;
    writeLE32(h0Input, p, type);
    p += 4;
    writeLE32(h0Input, p, password.length);
    p += 4;
    h0Input.set(password, p);
    p += password.length;
    writeLE32(h0Input, p, salt.length);
    p += 4;
    h0Input.set(salt, p);
    p += salt.length;
    writeLE32(h0Input, p, secret.length);
    p += 4;
    h0Input.set(secret, p);
    p += secret.length;
    writeLE32(h0Input, p, associatedData.length);
    p += 4;
    h0Input.set(associatedData, p);
    const h0 = blake2b(h0Input, 64);
    zeroize(h0Input);
    const memory = new Uint32Array(memoryBlocks * BLOCK_U32);
    const blockR = new Uint32Array(BLOCK_U32);
    const blockTmp = new Uint32Array(BLOCK_U32);
    const zeroBlock = new Uint32Array(BLOCK_U32);
    const inputBlock = new Uint32Array(BLOCK_U32);
    const addrBlock = new Uint32Array(BLOCK_U32);
    const seedBuf = new Uint8Array(72);
    try {
      seedBuf.set(h0, 0);
      for (let lane = 0; lane < parallelism; lane++) {
        const laneBase = lane * laneLength * BLOCK_U32;
        writeLE32(seedBuf, 64, 0);
        writeLE32(seedBuf, 68, lane);
        const b0 = blake2bLong(seedBuf, 1024);
        bytesToBlockU32(b0, memory, laneBase);
        zeroize(b0);
        writeLE32(seedBuf, 64, 1);
        const b1 = blake2bLong(seedBuf, 1024);
        bytesToBlockU32(b1, memory, laneBase + BLOCK_U32);
        zeroize(b1);
      }
      for (let pass = 0; pass < iterations; pass++) {
        for (let slice = 0; slice < SYNC_POINTS; slice++) {
          const dataIndependent = type === 1 || type === 2 && pass === 0 && slice < 2;
          for (let lane = 0; lane < parallelism; lane++) {
            let startingIndex = 0;
            if (dataIndependent) {
              inputBlock.fill(0);
              inputBlock[0] = pass >>> 0;
              inputBlock[2] = lane >>> 0;
              inputBlock[4] = slice >>> 0;
              inputBlock[6] = memoryBlocks >>> 0;
              inputBlock[8] = iterations >>> 0;
              inputBlock[10] = type >>> 0;
            }
            if (pass === 0 && slice === 0) {
              startingIndex = 2;
              if (dataIndependent) {
                nextAddresses(addrBlock, inputBlock, zeroBlock, blockR, blockTmp);
              }
            }
            let currOffset = lane * laneLength + slice * segmentLength + startingIndex;
            let prevOffset = currOffset % laneLength === 0 ? currOffset + laneLength - 1 : currOffset - 1;
            for (let index = startingIndex; index < segmentLength; index++, currOffset++, prevOffset++) {
              if (currOffset % laneLength === 1) {
                prevOffset = currOffset - 1;
              }
              let j1, j2;
              if (dataIndependent) {
                const addrIdx = index % ADDRESSES_IN_BLOCK;
                if (addrIdx === 0) {
                  nextAddresses(addrBlock, inputBlock, zeroBlock, blockR, blockTmp);
                }
                j1 = addrBlock[addrIdx << 1];
                j2 = addrBlock[(addrIdx << 1) + 1];
              } else {
                const prevU32 = prevOffset * BLOCK_U32;
                j1 = memory[prevU32];
                j2 = memory[prevU32 + 1];
              }
              const refLane = pass === 0 && slice === 0 ? lane : j2 % parallelism;
              const refIndex = indexAlpha(
                pass,
                slice,
                index,
                refLane === lane,
                laneLength,
                segmentLength,
                j1
              );
              const refOffset = refLane * laneLength + refIndex;
              fillBlock(
                memory,
                prevOffset * BLOCK_U32,
                memory,
                refOffset * BLOCK_U32,
                memory,
                currOffset * BLOCK_U32,
                pass > 0,
                blockR,
                blockTmp
              );
            }
          }
        }
      }
      const finalBlock = new Uint32Array(BLOCK_U32);
      for (let lane = 0; lane < parallelism; lane++) {
        const lastOff = (lane * laneLength + laneLength - 1) * BLOCK_U32;
        for (let i = 0; i < BLOCK_U32; i++) {
          finalBlock[i] = (finalBlock[i] ^ memory[lastOff + i]) >>> 0;
        }
      }
      const finalBytes = blockU32ToBytes(finalBlock, 0);
      const tag = blake2bLong(finalBytes, hashLength);
      zeroize(finalBlock, finalBytes);
      return tag;
    } finally {
      zeroize(h0, seedBuf, memory, blockR, blockTmp, zeroBlock, inputBlock, addrBlock);
    }
  }

  // src/crypto/kdf.js
  var import_meta = {};
  var KDF_ALGO = Object.freeze({
    ARGON2ID: "argon2id",
    PBKDF2_SHA256: "pbkdf2-sha256"
  });
  var KDF_LIMITS = Object.freeze({
    MIN_ARGON2_MEMORY_KIB: 32768,
    // 32 MiB minimum for newly created/upgraded vaults
    MAX_ARGON2_MEMORY_KIB: 524288,
    // 512 MiB anti-DoS ceiling
    MIN_ARGON2_ITERATIONS: 3,
    // Minimum 3 passes
    MAX_ARGON2_ITERATIONS: 64,
    MIN_PBKDF2_ITERATIONS: 6e5,
    // OWASP floor for PBKDF2-HMAC-SHA-256
    MAX_PBKDF2_ITERATIONS: 5e6,
    TARGET_MS: 950,
    // Calibrate to ~1 second on device
    KEY_LENGTH: 32
    // 256-bit KEK
  });
  var cachedWasmModule = void 0;
  async function loadVendoredArgon2Wasm() {
    if (cachedWasmModule !== void 0) return cachedWasmModule;
    if (typeof WebAssembly === "undefined") {
      cachedWasmModule = null;
      return null;
    }
    try {
      const vendorPath = ["..", "..", "vendor", "argon2.esm.js"].join("/");
      const mod = await import(
        /* @vite-ignore */
        vendorPath
      );
      if (typeof mod?.argon2id === "function") {
        cachedWasmModule = mod.argon2id;
        return cachedWasmModule;
      }
    } catch {
    }
    cachedWasmModule = null;
    return null;
  }
  function validateKdfSpec(spec, enforceMinimums = false) {
    if (!spec || typeof spec !== "object") {
      throw new KhaznaError("INVALID_KDF", "\u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0634\u062A\u0642\u0627\u0642 \u0627\u0644\u0645\u0641\u062A\u0627\u062D (KDF) \u063A\u064A\u0631 \u0635\u0627\u0644\u062D\u0629.", "Invalid KDF specification.");
    }
    const { kdf, params } = spec;
    if (!params || typeof params !== "object") {
      throw new KhaznaError("INVALID_KDF", "\u0645\u0639\u0627\u0645\u0644\u0627\u062A \u0627\u0634\u062A\u0642\u0627\u0642 \u0627\u0644\u0645\u0641\u062A\u0627\u062D \u0645\u0641\u0642\u0648\u062F\u0629.", "Missing KDF parameters.");
    }
    if (kdf === KDF_ALGO.ARGON2ID) {
      const { memoryKiB, iterations, parallelism = 1 } = params;
      const minMem = enforceMinimums ? KDF_LIMITS.MIN_ARGON2_MEMORY_KIB : 8 * parallelism;
      const minIter = enforceMinimums ? KDF_LIMITS.MIN_ARGON2_ITERATIONS : 1;
      if (!Number.isInteger(memoryKiB) || memoryKiB < minMem || memoryKiB > KDF_LIMITS.MAX_ARGON2_MEMORY_KIB || !Number.isInteger(iterations) || iterations < minIter || iterations > KDF_LIMITS.MAX_ARGON2_ITERATIONS || !Number.isInteger(parallelism) || parallelism < 1 || parallelism > 8) {
        throw new KhaznaError(
          "INVALID_KDF_PARAMS",
          "\u0645\u0639\u0627\u0645\u0644\u0627\u062A Argon2id \u062E\u0627\u0631\u062C \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0622\u0645\u0646 \u0627\u0644\u0645\u0633\u0645\u0648\u062D \u0628\u0647.",
          "Argon2id parameters out of allowed safety bounds."
        );
      }
      return;
    }
    if (kdf === KDF_ALGO.PBKDF2_SHA256) {
      const { iterations } = params;
      const minIter = enforceMinimums ? KDF_LIMITS.MIN_PBKDF2_ITERATIONS : 1e3;
      if (!Number.isInteger(iterations) || iterations < minIter || iterations > KDF_LIMITS.MAX_PBKDF2_ITERATIONS) {
        throw new KhaznaError(
          "INVALID_KDF_PARAMS",
          "\u0639\u062F\u062F \u062F\u0648\u0631\u0627\u062A PBKDF2 \u062E\u0627\u0631\u062C \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0622\u0645\u0646 \u0627\u0644\u0645\u0633\u0645\u0648\u062D \u0628\u0647.",
          "PBKDF2 iterations out of allowed safety bounds."
        );
      }
      return;
    }
    throw new KhaznaError(
      "UNSUPPORTED_KDF",
      `\u062E\u0648\u0627\u0631\u0632\u0645\u064A\u0629 \u0627\u0634\u062A\u0642\u0627\u0642 \u0627\u0644\u0645\u0641\u062A\u0627\u062D (${kdf}) \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645\u0629 \u0641\u064A \u0647\u0630\u0627 \u0627\u0644\u0625\u0635\u062F\u0627\u0631.`,
      `Unsupported KDF algorithm: ${kdf}`
    );
  }
  async function derivePbkdf2Sha256(passwordBytes, salt, iterations, hashLength = 32) {
    const baseKey = await globalThis.crypto.subtle.importKey(
      "raw",
      passwordBytes,
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations
      },
      baseKey,
      hashLength * 8
    );
    return new Uint8Array(bits);
  }
  async function deriveKeyBytesDirect(password, salt, spec, opts = {}) {
    validateKdfSpec(spec, false);
    const pwdBytes = typeof password === "string" ? utf8Encode(password) : new Uint8Array(password);
    try {
      if (spec.kdf === KDF_ALGO.ARGON2ID) {
        const { memoryKiB, iterations, parallelism = 1 } = spec.params;
        if (!opts.preferPureJs) {
          const wasmFn = await loadVendoredArgon2Wasm();
          if (wasmFn) {
            const raw2 = await wasmFn({
              password: pwdBytes,
              salt,
              parallelism,
              iterations,
              memorySize: memoryKiB,
              hashLength: KDF_LIMITS.KEY_LENGTH,
              outputType: "binary"
            });
            return { keyBytes: new Uint8Array(raw2), engine: "argon2id-wasm" };
          }
        }
        const raw = argon2idPure({
          password: pwdBytes,
          salt,
          memorySize: memoryKiB,
          iterations,
          parallelism,
          hashLength: KDF_LIMITS.KEY_LENGTH
        });
        return { keyBytes: raw, engine: "argon2id-js" };
      }
      if (spec.kdf === KDF_ALGO.PBKDF2_SHA256) {
        const raw = await derivePbkdf2Sha256(
          pwdBytes,
          salt,
          spec.params.iterations,
          KDF_LIMITS.KEY_LENGTH
        );
        return { keyBytes: raw, engine: "webcrypto-pbkdf2" };
      }
      throw new KhaznaError("UNSUPPORTED_KDF", "\u062E\u0648\u0627\u0631\u0632\u0645\u064A\u0629 KDF \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645\u0629.", "Unsupported KDF.");
    } finally {
      zeroize(pwdBytes);
    }
  }
  async function deriveKeyBytes(password, salt, spec, opts = {}) {
    const useWorker = opts.useWorker !== false && typeof Worker === "function";
    if (useWorker && spec.kdf === KDF_ALGO.ARGON2ID) {
      try {
        return await runInKdfWorker(password, salt, spec, opts);
      } catch {
      }
    }
    return deriveKeyBytesDirect(password, salt, spec, opts);
  }
  function runInKdfWorker(password, salt, spec, opts) {
    return new Promise((resolve, reject) => {
      let workerUrl;
      try {
        workerUrl = typeof import_meta !== "undefined" && import_meta?.url ? new URL("./kdf-worker.js", import_meta.url) : null;
      } catch {
        workerUrl = null;
      }
      if (!workerUrl) {
        deriveKeyBytesDirect(password, salt, spec, opts).then(resolve, reject);
        return;
      }
      const worker = new Worker(workerUrl, { type: "module" });
      const pwdBytes = typeof password === "string" ? utf8Encode(password) : new Uint8Array(password);
      const saltCopy = new Uint8Array(salt);
      const cleanup = () => {
        try {
          worker.terminate();
        } catch {
        }
        zeroize(pwdBytes, saltCopy);
      };
      worker.onmessage = (ev) => {
        const msg = ev.data;
        cleanup();
        if (msg?.ok) {
          resolve({ keyBytes: new Uint8Array(msg.keyBytes), engine: msg.engine });
        } else {
          reject(new KhaznaError(
            msg?.code || "KDF_WORKER_ERROR",
            msg?.ar || "\u062A\u0639\u0630\u0651\u0631 \u0627\u0634\u062A\u0642\u0627\u0642 \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u062A\u0634\u0641\u064A\u0631.",
            msg?.en || "KDF worker error."
          ));
        }
      };
      worker.onerror = (err) => {
        cleanup();
        reject(err);
      };
      worker.postMessage(
        {
          passwordBuffer: pwdBytes.buffer,
          saltBuffer: saltCopy.buffer,
          spec,
          preferPureJs: Boolean(opts.preferPureJs)
        },
        [pwdBytes.buffer, saltCopy.buffer]
      );
    });
  }
  async function calibrateKdf(opts = {}) {
    const targetMs = opts.targetMs ?? KDF_LIMITS.TARGET_MS;
    const samplePassword = randomBytes(16);
    const sampleSalt = randomBytes(16);
    try {
      if (!opts.forcePbkdf2) {
        try {
          let memoryKiB = KDF_LIMITS.MIN_ARGON2_MEMORY_KIB;
          let iterations2 = KDF_LIMITS.MIN_ARGON2_ITERATIONS;
          const parallelism = 1;
          const t02 = performance.now();
          const probe2 = await deriveKeyBytes(
            samplePassword,
            sampleSalt,
            { kdf: KDF_ALGO.ARGON2ID, params: { memoryKiB, iterations: iterations2, parallelism } },
            { useWorker: opts.useWorker }
          );
          const baselineMs = Math.max(1, performance.now() - t02);
          zeroize(probe2.keyBytes);
          if (baselineMs * 2 <= targetMs * 1.15) {
            const t1 = performance.now();
            const probe64 = await deriveKeyBytes(
              samplePassword,
              sampleSalt,
              { kdf: KDF_ALGO.ARGON2ID, params: { memoryKiB: 65536, iterations: iterations2, parallelism } },
              { useWorker: opts.useWorker }
            );
            const ms64 = Math.max(1, performance.now() - t1);
            zeroize(probe64.keyBytes);
            memoryKiB = 65536;
            if (ms64 < targetMs * 0.8) {
              const scaled = Math.round(iterations2 * targetMs / ms64);
              iterations2 = Math.min(8, Math.max(KDF_LIMITS.MIN_ARGON2_ITERATIONS, scaled));
            }
            return {
              kdf: KDF_ALGO.ARGON2ID,
              params: { memoryKiB, iterations: iterations2, parallelism },
              engine: probe64.engine,
              elapsedMs: Math.round(ms64 * (iterations2 / KDF_LIMITS.MIN_ARGON2_ITERATIONS))
            };
          }
          if (baselineMs < targetMs * 0.75) {
            const scaled = Math.round(iterations2 * targetMs / baselineMs);
            iterations2 = Math.min(6, Math.max(KDF_LIMITS.MIN_ARGON2_ITERATIONS, scaled));
          }
          return {
            kdf: KDF_ALGO.ARGON2ID,
            params: { memoryKiB, iterations: iterations2, parallelism },
            engine: probe2.engine,
            elapsedMs: Math.round(baselineMs * (iterations2 / KDF_LIMITS.MIN_ARGON2_ITERATIONS))
          };
        } catch {
        }
      }
      const probeIterations = 1e5;
      const t0 = performance.now();
      const probe = await derivePbkdf2Sha256(samplePassword, sampleSalt, probeIterations, 32);
      const probeMs = Math.max(1, performance.now() - t0);
      zeroize(probe);
      const estimated = Math.round(probeIterations * targetMs / probeMs);
      const rounded = Math.ceil(estimated / 5e4) * 5e4;
      const iterations = Math.min(
        KDF_LIMITS.MAX_PBKDF2_ITERATIONS,
        Math.max(KDF_LIMITS.MIN_PBKDF2_ITERATIONS, rounded)
      );
      return {
        kdf: KDF_ALGO.PBKDF2_SHA256,
        params: { iterations },
        engine: "webcrypto-pbkdf2",
        elapsedMs: Math.round(probeMs * iterations / probeIterations)
      };
    } finally {
      zeroize(samplePassword, sampleSalt);
    }
  }

  // src/crypto/vault-crypto.js
  var VAULT_HEADER_VERSION = 1;
  var RECORD_SCHEMA_VERSION = 1;
  var BACKUP_FORMAT_ID = "khazna-vault-backup";
  var BACKUP_FORMAT_VERSION = 1;
  var MIN_MASTER_PASSWORD_LEN = 12;
  var HKDF_INFO_RECOVERY = utf8Encode("khazna-v1-recovery-dek-wrap");
  var HKDF_INFO_WEBAUTHN = utf8Encode("khazna-v1-webauthn-prf-dek-wrap");
  var CHARSETS = Object.freeze({
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{}:;,.?/~",
    lookalikes: /[0Oo1Il|]/g
  });
  var PASSPHRASE_WORDS = Object.freeze([
    "amber",
    "anchor",
    "apple",
    "apron",
    "arbor",
    "arrow",
    "atlas",
    "autumn",
    "badge",
    "baker",
    "bamboo",
    "banner",
    "barley",
    "barrel",
    "basalt",
    "basket",
    "beacon",
    "beaver",
    "berry",
    "birch",
    "bison",
    "blanket",
    "blossom",
    "boulder",
    "branch",
    "breeze",
    "bridge",
    "bronze",
    "brook",
    "bucket",
    "button",
    "cabin",
    "cactus",
    "camel",
    "candle",
    "cannon",
    "canopy",
    "canyon",
    "canvas",
    "captain",
    "caravan",
    "carbon",
    "carpet",
    "carrot",
    "castle",
    "cedar",
    "cellar",
    "chalk",
    "chapter",
    "cherry",
    "chisel",
    "cider",
    "cinnamon",
    "circle",
    "citadel",
    "citrus",
    "clay",
    "cliff",
    "clover",
    "cobalt",
    "coffee",
    "comet",
    "compass",
    "copper",
    "coral",
    "corner",
    "cotton",
    "cougar",
    "cradle",
    "crater",
    "crayon",
    "creek",
    "cricket",
    "crown",
    "crystal",
    "curtain",
    "cushion",
    "cypress",
    "dagger",
    "daisy",
    "dancer",
    "dawn",
    "delta",
    "desert",
    "diamond",
    "dolphin",
    "domino",
    "donkey",
    "dragon",
    "drawer",
    "drift",
    "drum",
    "eagle",
    "earth",
    "eclipse",
    "elder",
    "ember",
    "emerald",
    "engine",
    "falcon",
    "feather",
    "fennel",
    "ferret",
    "fern",
    "fiddle",
    "fig",
    "filter",
    "finch",
    "fjord",
    "flame",
    "flannel",
    "flint",
    "flower",
    "flute",
    "forest",
    "fossil",
    "fountain",
    "fox",
    "frost",
    "funnel",
    "galaxy",
    "garden",
    "garlic",
    "garnet",
    "gazelle",
    "geyser",
    "ginger",
    "glacier",
    "glider",
    "globe",
    "granite",
    "grape",
    "gravel",
    "griffin",
    "grove",
    "guitar",
    "hammer",
    "harbor",
    "harvest",
    "hawk",
    "hazel",
    "heather",
    "helmet",
    "heron",
    "hickory",
    "hollow",
    "honey",
    "horizon",
    "hornet",
    "humble",
    "ibis",
    "icicle",
    "indigo",
    "island",
    "ivory",
    "jacket",
    "jade",
    "jaguar",
    "jasmine",
    "jasper",
    "jigsaw",
    "juniper",
    "kayak",
    "kettle",
    "kestrel",
    "kingdom",
    "kitten",
    "koala",
    "ladder",
    "lagoon",
    "lantern",
    "larch",
    "laser",
    "laurel",
    "lava",
    "lemon",
    "leopard",
    "library",
    "lichen",
    "lilac",
    "linden",
    "linen",
    "lizard",
    "lobster",
    "locket",
    "lotus",
    "lumber",
    "lunar",
    "lynx",
    "magnet",
    "magpie",
    "mango",
    "mantle",
    "maple",
    "marble",
    "market",
    "marmot",
    "meadow",
    "melon",
    "mercury",
    "meteor",
    "miller",
    "mint",
    "mirror",
    "mitten",
    "monarch",
    "monkey",
    "monsoon",
    "mosaic",
    "moss",
    "mountain",
    "muffin",
    "mulberry",
    "mustard",
    "narwhal",
    "nebula",
    "nectar",
    "needle",
    "nettle",
    "nickel",
    "nimbus",
    "noodle",
    "nutmeg",
    "oasis",
    "obsidian",
    "ocean",
    "ocelot",
    "olive",
    "onyx",
    "opal",
    "orange",
    "orchard",
    "orchid",
    "oriole",
    "osprey",
    "otter",
    "owl",
    "oyster",
    "paddle",
    "palace",
    "palm",
    "panda",
    "panther",
    "papaya",
    "paper",
    "parrot",
    "parsley",
    "pasture",
    "pebble",
    "pelican",
    "pencil",
    "penguin",
    "peony",
    "pepper",
    "perch",
    "petrel"
  ]);
  function validateMasterPasswordPolicy(password) {
    if (typeof password !== "string") {
      throw new KhaznaError(
        "WEAK_MASTER_PASSWORD",
        "\u064A\u062C\u0628 \u0625\u062F\u062E\u0627\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0631\u0626\u064A\u0633\u064A\u0629 \u0635\u0627\u0644\u062D\u0629.",
        "Master password must be a string."
      );
    }
    const codePoints = Array.from(password).length;
    if (codePoints < MIN_MASTER_PASSWORD_LEN) {
      throw new KhaznaError(
        "MASTER_PASSWORD_TOO_SHORT",
        `\u064A\u062C\u0628 \u0623\u0644\u0627 \u062A\u0642\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0639\u0646 ${MIN_MASTER_PASSWORD_LEN} \u062D\u0631\u0641\u0627\u064B.`,
        `Master password must be at least ${MIN_MASTER_PASSWORD_LEN} characters long.`
      );
    }
  }
  async function deriveHkdfWrapKey(ikm, salt, info) {
    const baseKey = await globalThis.crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    return globalThis.crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }
  async function importAesWrapKey(rawKek) {
    return globalThis.crypto.subtle.importKey(
      "raw",
      rawKek,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }
  async function wrapDek(extractableDek, kek, vaultId, wrapperId) {
    const iv = randomBytes(12);
    const additionalData = buildAAD({
      id: `wrapper-${wrapperId}`,
      type: "dek-wrapper",
      schemaVersion: VAULT_HEADER_VERSION,
      vaultId
    });
    const wrapped = await globalThis.crypto.subtle.wrapKey(
      "raw",
      extractableDek,
      kek,
      { name: "AES-GCM", iv, additionalData }
    );
    return {
      iv: bytesToBase64(iv),
      wrappedDek: bytesToBase64(new Uint8Array(wrapped))
    };
  }
  async function unwrapDek(wrapper, kek, vaultId, wrapperId, extractable = false) {
    const iv = base64ToBytes(wrapper.iv);
    const wrappedBytes = base64ToBytes(wrapper.wrappedDek);
    const additionalData = buildAAD({
      id: `wrapper-${wrapperId}`,
      type: "dek-wrapper",
      schemaVersion: VAULT_HEADER_VERSION,
      vaultId
    });
    return globalThis.crypto.subtle.unwrapKey(
      "raw",
      wrappedBytes,
      kek,
      { name: "AES-GCM", iv, additionalData },
      { name: "AES-GCM", length: 256 },
      extractable,
      ["encrypt", "decrypt"]
    );
  }
  async function createVaultCrypto({
    masterPassword,
    kdfSpec,
    enforceMinimums = true,
    useWorker = true
  }) {
    validateMasterPasswordPolicy(masterPassword);
    validateKdfSpec(kdfSpec, enforceMinimums);
    const vaultId = randomId("vault");
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const tempDek = await globalThis.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const passwordSalt = randomBytes(16);
    const recoveryKeyBytes = randomBytes(32);
    const recoverySalt = randomBytes(16);
    let passwordKekBytes = null;
    try {
      const derived = await deriveKeyBytes(masterPassword, passwordSalt, kdfSpec, { useWorker });
      passwordKekBytes = derived.keyBytes;
      const passwordKek = await importAesWrapKey(passwordKekBytes);
      const passwordWrapped = await wrapDek(tempDek, passwordKek, vaultId, "password");
      const recoveryKek = await deriveHkdfWrapKey(recoveryKeyBytes, recoverySalt, HKDF_INFO_RECOVERY);
      const recoveryWrapped = await wrapDek(tempDek, recoveryKek, vaultId, "recovery");
      const recoveryKeyFormatted = await encodeRecoveryKey(recoveryKeyBytes);
      const activeDek = await unwrapDek(passwordWrapped, passwordKek, vaultId, "password", false);
      const header = {
        version: VAULT_HEADER_VERSION,
        vaultId,
        schemaVersion: RECORD_SCHEMA_VERSION,
        kdf: kdfSpec.kdf,
        kdfParams: { ...kdfSpec.params },
        wrappers: {
          password: {
            salt: bytesToBase64(passwordSalt),
            iv: passwordWrapped.iv,
            wrappedDek: passwordWrapped.wrappedDek,
            updatedAt: now
          },
          recovery: {
            salt: bytesToBase64(recoverySalt),
            iv: recoveryWrapped.iv,
            wrappedDek: recoveryWrapped.wrappedDek,
            createdAt: now
          },
          webauthn: null
        },
        security: {
          failedAttempts: 0,
          lockoutUntil: 0,
          wipeAfterFailures: 0,
          lastMasterUnlockAt: Date.now()
        },
        createdAt: now,
        updatedAt: now
      };
      return {
        header,
        dek: activeDek,
        recoveryKeyFormatted,
        kdfEngine: derived.engine
      };
    } finally {
      zeroize(passwordKekBytes, recoveryKeyBytes);
    }
  }
  async function unwrapDekWithPassword(header, masterPassword, opts = {}) {
    const pwWrapper = header?.wrappers?.password;
    if (!pwWrapper?.salt || !pwWrapper?.iv || !pwWrapper?.wrappedDek) {
      throw new KhaznaError(
        "CORRUPT_HEADER",
        "\u062A\u0631\u0648\u064A\u0633\u0629 \u0627\u0644\u062E\u0632\u0646\u0629 \u062A\u0627\u0644\u0641\u0629 \u0623\u0648 \u063A\u064A\u0631 \u0645\u0643\u062A\u0645\u0644\u0629.",
        "Vault header is missing password wrapper."
      );
    }
    const salt = base64ToBytes(pwWrapper.salt);
    let kekBytes = null;
    try {
      const derived = await deriveKeyBytes(
        masterPassword,
        salt,
        { kdf: header.kdf, params: header.kdfParams },
        { useWorker: opts.useWorker }
      );
      kekBytes = derived.keyBytes;
      const kek = await importAesWrapKey(kekBytes);
      const dek = await unwrapDek(
        pwWrapper,
        kek,
        header.vaultId,
        "password",
        Boolean(opts.extractable)
      );
      return { dek, kdfEngine: derived.engine };
    } catch (err) {
      if (err instanceof KhaznaError) throw err;
      throw new KhaznaError(
        "WRONG_PASSWORD",
        "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629.",
        "Incorrect master password.",
        err
      );
    } finally {
      zeroize(kekBytes);
    }
  }
  async function unwrapDekWithRecoveryKey(header, formattedRecoveryKey, opts = {}) {
    const recWrapper = header?.wrappers?.recovery;
    if (!recWrapper?.salt || !recWrapper?.iv || !recWrapper?.wrappedDek) {
      throw new KhaznaError(
        "NO_RECOVERY_WRAPPER",
        "\u0644\u0627 \u064A\u0648\u062C\u062F \u0645\u0641\u062A\u0627\u062D \u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0645\u0647\u064A\u0651\u0623 \u0644\u0647\u0630\u0647 \u0627\u0644\u062E\u0632\u0646\u0629.",
        "No recovery wrapper configured for this vault."
      );
    }
    const recoveryKeyBytes = await decodeRecoveryKey(formattedRecoveryKey);
    const salt = base64ToBytes(recWrapper.salt);
    try {
      const kek = await deriveHkdfWrapKey(recoveryKeyBytes, salt, HKDF_INFO_RECOVERY);
      return await unwrapDek(
        recWrapper,
        kek,
        header.vaultId,
        "recovery",
        Boolean(opts.extractable)
      );
    } catch (err) {
      if (err instanceof KhaznaError) throw err;
      throw new KhaznaError(
        "WRONG_RECOVERY_KEY",
        "\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0644\u0627 \u064A\u0637\u0627\u0628\u0642 \u0647\u0630\u0647 \u0627\u0644\u062E\u0632\u0646\u0629.",
        "Recovery key does not match this vault.",
        err
      );
    } finally {
      zeroize(recoveryKeyBytes);
    }
  }
  async function createWebAuthnPrfWrapper(header, extractableDek, prfOutput, meta) {
    const hkdfSalt = randomBytes(16);
    try {
      const kek = await deriveHkdfWrapKey(prfOutput, hkdfSalt, HKDF_INFO_WEBAUTHN);
      const wrapped = await wrapDek(extractableDek, kek, header.vaultId, "webauthn");
      return {
        mode: "prf",
        credentialId: meta.credentialId,
        prfSalt: meta.prfSaltB64,
        hkdfSalt: bytesToBase64(hkdfSalt),
        iv: wrapped.iv,
        wrappedDek: wrapped.wrappedDek,
        createdAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    } finally {
      zeroize(hkdfSalt);
    }
  }
  async function unwrapDekWithWebAuthnPrf(header, prfOutput, opts = {}) {
    const wa = header?.wrappers?.webauthn;
    if (!wa || wa.mode !== "prf" || !wa.hkdfSalt || !wa.iv || !wa.wrappedDek) {
      throw new KhaznaError(
        "NO_WEBAUTHN_PRF",
        "\u0641\u062A\u062D \u0627\u0644\u0628\u0635\u0645\u0629 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 (PRF) \u063A\u064A\u0631 \u0645\u0641\u0639\u0651\u0644 \u0644\u0647\u0630\u0647 \u0627\u0644\u062E\u0632\u0646\u0629.",
        "WebAuthn PRF biometric wrapper is not configured."
      );
    }
    const hkdfSalt = base64ToBytes(wa.hkdfSalt);
    try {
      const kek = await deriveHkdfWrapKey(prfOutput, hkdfSalt, HKDF_INFO_WEBAUTHN);
      return await unwrapDek(wa, kek, header.vaultId, "webauthn", Boolean(opts.extractable));
    } catch (err) {
      if (err instanceof KhaznaError) throw err;
      throw new KhaznaError(
        "WEBAUTHN_UNWRAP_FAILED",
        "\u0641\u0634\u0644 \u0641\u0643 \u062A\u0634\u0641\u064A\u0631 \u0627\u0644\u062E\u0632\u0646\u0629 \u0628\u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0627\u0644\u0628\u0635\u0645\u0629 \u2014 \u0627\u0633\u062A\u062E\u062F\u0645 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629.",
        "Failed to unwrap vault key with WebAuthn PRF output.",
        err
      );
    }
  }
  async function rewrapMasterPassword({
    header,
    currentPassword,
    recoveryKey,
    newMasterPassword,
    newKdfSpec,
    enforceMinimums = true,
    useWorker = true
  }) {
    validateMasterPasswordPolicy(newMasterPassword);
    const targetKdf = newKdfSpec || { kdf: header.kdf, params: header.kdfParams };
    validateKdfSpec(targetKdf, enforceMinimums);
    let tempDek = null;
    if (typeof currentPassword === "string" && currentPassword.length > 0) {
      const res = await unwrapDekWithPassword(header, currentPassword, {
        extractable: true,
        useWorker
      });
      tempDek = res.dek;
    } else if (typeof recoveryKey === "string" && recoveryKey.length > 0) {
      tempDek = await unwrapDekWithRecoveryKey(header, recoveryKey, { extractable: true });
    } else {
      throw new KhaznaError(
        "AUTH_REQUIRED",
        "\u064A\u062C\u0628 \u062A\u0623\u0643\u064A\u062F \u0647\u0648\u064A\u062A\u0643 \u0628\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u062D\u0627\u0644\u064A\u0629 \u0623\u0648 \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0623\u0648\u0644\u0627\u064B.",
        "Current password or recovery key is required to change master password."
      );
    }
    const newSalt = randomBytes(16);
    let newKekBytes = null;
    try {
      const derived = await deriveKeyBytes(newMasterPassword, newSalt, targetKdf, { useWorker });
      newKekBytes = derived.keyBytes;
      const newKek = await importAesWrapKey(newKekBytes);
      const wrapped = await wrapDek(tempDek, newKek, header.vaultId, "password");
      const activeDek = await unwrapDek(wrapped, newKek, header.vaultId, "password", false);
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const updatedHeader = {
        ...header,
        kdf: targetKdf.kdf,
        kdfParams: { ...targetKdf.params },
        wrappers: {
          ...header.wrappers,
          password: {
            salt: bytesToBase64(newSalt),
            iv: wrapped.iv,
            wrappedDek: wrapped.wrappedDek,
            updatedAt: now
          }
        },
        security: {
          ...header.security,
          failedAttempts: 0,
          lockoutUntil: 0,
          lastMasterUnlockAt: Date.now()
        },
        updatedAt: now
      };
      return { updatedHeader, dek: activeDek, kdfEngine: derived.engine };
    } finally {
      tempDek = null;
      zeroize(newKekBytes);
    }
  }
  async function rotateRecoveryKey({ header, masterPassword, useWorker = true }) {
    const { dek: tempDek } = await unwrapDekWithPassword(header, masterPassword, {
      extractable: true,
      useWorker
    });
    const recoveryKeyBytes = randomBytes(32);
    const recoverySalt = randomBytes(16);
    try {
      const recoveryKek = await deriveHkdfWrapKey(recoveryKeyBytes, recoverySalt, HKDF_INFO_RECOVERY);
      const wrapped = await wrapDek(tempDek, recoveryKek, header.vaultId, "recovery");
      const recoveryKeyFormatted = await encodeRecoveryKey(recoveryKeyBytes);
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const updatedHeader = {
        ...header,
        wrappers: {
          ...header.wrappers,
          recovery: {
            salt: bytesToBase64(recoverySalt),
            iv: wrapped.iv,
            wrappedDek: wrapped.wrappedDek,
            createdAt: now
          }
        },
        updatedAt: now
      };
      return { updatedHeader, recoveryKeyFormatted };
    } finally {
      zeroize(recoveryKeyBytes);
    }
  }
  async function encryptRecord(dek, {
    id,
    type,
    vaultId,
    data,
    schemaVersion = RECORD_SCHEMA_VERSION,
    deletedAt = null,
    createdAt,
    updatedAt
  }) {
    if (!dek) {
      throw new KhaznaError("VAULT_LOCKED", "\u0627\u0644\u062E\u0632\u0646\u0629 \u0645\u0642\u0641\u0644\u0629 \u062D\u0627\u0644\u064A\u0627\u064B.", "Vault is locked.");
    }
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const iv = randomBytes(12);
    const additionalData = buildAAD({ id, type, schemaVersion, vaultId });
    const plaintext = utf8Encode(JSON.stringify(data));
    try {
      const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData },
        dek,
        plaintext
      );
      return {
        id,
        type,
        schemaVersion,
        iv: bytesToBase64(iv),
        ct: bytesToBase64(new Uint8Array(ciphertext)),
        createdAt: createdAt || now,
        updatedAt: updatedAt || now,
        deletedAt: deletedAt ?? null
      };
    } finally {
      zeroize(plaintext);
    }
  }
  async function decryptRecord(dek, envelope, vaultId) {
    if (!dek) {
      throw new KhaznaError("VAULT_LOCKED", "\u0627\u0644\u062E\u0632\u0646\u0629 \u0645\u0642\u0641\u0644\u0629 \u062D\u0627\u0644\u064A\u0627\u064B.", "Vault is locked.");
    }
    if (!envelope || !envelope.id || !envelope.type || !envelope.iv || !envelope.ct) {
      throw new KhaznaError(
        "CORRUPT_RECORD",
        "\u0623\u062D\u062F \u0627\u0644\u0633\u062C\u0644\u0627\u062A \u0627\u0644\u0645\u0634\u0641\u0651\u0631\u0629 \u062A\u0627\u0644\u0641 \u0623\u0648 \u0646\u0627\u0642\u0635 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A.",
        "Encrypted record envelope is malformed."
      );
    }
    const schemaVersion = envelope.schemaVersion ?? RECORD_SCHEMA_VERSION;
    const iv = base64ToBytes(envelope.iv);
    const ct = base64ToBytes(envelope.ct);
    const additionalData = buildAAD({
      id: envelope.id,
      type: envelope.type,
      schemaVersion,
      vaultId
    });
    let decryptedBuf;
    try {
      decryptedBuf = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData },
        dek,
        ct
      );
    } catch (err) {
      throw new KhaznaError(
        "TAMPER_OR_CORRUPT",
        "\u0641\u0634\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u0633\u062C\u0644 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 \u2014 \u0642\u062F \u064A\u0643\u0648\u0646 \u062A\u0627\u0644\u0641\u0627\u064B \u0623\u0648 \u062A\u0645 \u0627\u0644\u062A\u0644\u0627\u0639\u0628 \u0628\u0647 \u0623\u0648 \u0627\u0644\u0645\u0641\u062A\u0627\u062D \u062E\u0627\u0637\u0626.",
        "AES-GCM authentication failed: record tampered, corrupted, or wrong key.",
        err
      );
    }
    const plainBytes = new Uint8Array(decryptedBuf);
    try {
      const jsonText = utf8Decode(plainBytes);
      const data = JSON.parse(jsonText);
      return {
        id: envelope.id,
        type: envelope.type,
        schemaVersion,
        createdAt: envelope.createdAt,
        updatedAt: envelope.updatedAt,
        deletedAt: envelope.deletedAt ?? null,
        data
      };
    } catch (err) {
      throw new KhaznaError(
        "CORRUPT_PAYLOAD",
        "\u062A\u0639\u0630\u0651\u0631 \u0642\u0631\u0627\u0621\u0629 \u0645\u062D\u062A\u0648\u0649 \u0627\u0644\u0633\u062C\u0644 \u0628\u0639\u062F \u0641\u0643 \u0627\u0644\u062A\u0634\u0641\u064A\u0631.",
        "Decrypted record JSON payload is corrupted.",
        err
      );
    } finally {
      zeroize(plainBytes);
    }
  }
  async function encryptVaultBackup(payload, backupPassword, kdfSpec, opts = {}) {
    if (typeof backupPassword !== "string" || backupPassword.length < 8) {
      throw new KhaznaError(
        "WEAK_BACKUP_PASSWORD",
        "\u064A\u062C\u0628 \u0623\u0644\u0627 \u062A\u0642\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0646\u0633\u062E\u0629 \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 \u0639\u0646 \u0668 \u0623\u062D\u0631\u0641 (\u0648\u064A\u064F\u0641\u0636\u0651\u0644 \u0661\u0662 \u062D\u0631\u0641\u0627\u064B \u0641\u0623\u0643\u062B\u0631).",
        "Backup password must be at least 8 characters."
      );
    }
    validateKdfSpec(kdfSpec, opts.enforceMinimums ?? true);
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const additionalData = buildAAD({
      id: "backup",
      type: BACKUP_FORMAT_ID,
      schemaVersion: BACKUP_FORMAT_VERSION,
      vaultId: "khazna-backup"
    });
    let keyBytes = null;
    const plainBytes = utf8Encode(JSON.stringify(payload));
    try {
      const derived = await deriveKeyBytes(backupPassword, salt, kdfSpec, {
        useWorker: opts.useWorker
      });
      keyBytes = derived.keyBytes;
      const key = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const ct = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData },
        key,
        plainBytes
      );
      const envelope = {
        format: BACKUP_FORMAT_ID,
        version: BACKUP_FORMAT_VERSION,
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        kdf: kdfSpec.kdf,
        kdfParams: { ...kdfSpec.params },
        salt: bytesToBase64(salt),
        iv: bytesToBase64(iv),
        ct: bytesToBase64(new Uint8Array(ct))
      };
      return JSON.stringify(envelope, null, 2);
    } finally {
      zeroize(keyBytes, plainBytes);
    }
  }
  async function decryptVaultBackup(rawText, backupPassword, opts = {}) {
    let envelope;
    try {
      envelope = JSON.parse(rawText);
    } catch (err) {
      throw new KhaznaError(
        "INVALID_VAULT_FILE",
        "\u0645\u0644\u0641 \u0627\u0644\u0646\u0633\u062E\u0629 \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 (.vault) \u0644\u064A\u0633 \u0628\u0635\u064A\u063A\u0629 JSON \u0635\u0627\u0644\u062D\u0629.",
        "Invalid .vault backup JSON format.",
        err
      );
    }
    if (!envelope || envelope.format !== BACKUP_FORMAT_ID || envelope.version !== BACKUP_FORMAT_VERSION || !envelope.salt || !envelope.iv || !envelope.ct) {
      throw new KhaznaError(
        "UNSUPPORTED_VAULT_FILE",
        "\u0635\u064A\u063A\u0629 \u0645\u0644\u0641 .vault \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645\u0629 \u0623\u0648 \u062A\u0627\u0644\u0641\u0629.",
        "Unsupported or corrupted .vault backup file."
      );
    }
    const salt = base64ToBytes(envelope.salt);
    const iv = base64ToBytes(envelope.iv);
    const ct = base64ToBytes(envelope.ct);
    const additionalData = buildAAD({
      id: "backup",
      type: BACKUP_FORMAT_ID,
      schemaVersion: envelope.version,
      vaultId: "khazna-backup"
    });
    let keyBytes = null;
    let plainBytes = null;
    try {
      const derived = await deriveKeyBytes(
        backupPassword,
        salt,
        { kdf: envelope.kdf, params: envelope.kdfParams },
        { useWorker: opts.useWorker }
      );
      keyBytes = derived.keyBytes;
      const key = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const decrypted = await globalThis.crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData },
        key,
        ct
      );
      plainBytes = new Uint8Array(decrypted);
      const payload = JSON.parse(utf8Decode(plainBytes));
      return {
        payload,
        meta: {
          version: envelope.version,
          createdAt: envelope.createdAt,
          kdf: envelope.kdf
        }
      };
    } catch (err) {
      if (err instanceof KhaznaError) throw err;
      throw new KhaznaError(
        "BACKUP_DECRYPT_FAILED",
        "\u062A\u0639\u0630\u0651\u0631 \u0641\u0643 \u062A\u0634\u0641\u064A\u0631 \u0645\u0644\u0641 .vault \u2014 \u062A\u0623\u0643\u062F \u0645\u0646 \u0635\u062D\u0629 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0646\u0633\u062E\u0629 \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 \u0623\u0648 \u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u0645\u0644\u0641.",
        "Failed to decrypt .vault backup (wrong password or tampered file).",
        err
      );
    } finally {
      zeroize(keyBytes, plainBytes);
    }
  }
  function generatePassword({
    length = 20,
    lower = true,
    upper = true,
    digits = true,
    symbols = true,
    excludeLookalikes = false
  } = {}) {
    const safeLen = Math.min(128, Math.max(8, Math.floor(length)));
    const activePools = [];
    const filterPool = (s) => excludeLookalikes ? s.replace(CHARSETS.lookalikes, "") : s;
    if (lower) activePools.push(filterPool(CHARSETS.lower));
    if (upper) activePools.push(filterPool(CHARSETS.upper));
    if (digits) activePools.push(filterPool(CHARSETS.digits));
    if (symbols) activePools.push(filterPool(CHARSETS.symbols));
    const validPools = activePools.filter((p) => p.length > 0);
    if (validPools.length === 0) {
      throw new KhaznaError(
        "NO_CHARSET_SELECTED",
        "\u0627\u062E\u062A\u0631 \u0645\u062C\u0645\u0648\u0639\u0629 \u0623\u062D\u0631\u0641 \u0648\u0627\u062D\u062F\u0629 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644 \u0644\u062A\u0648\u0644\u064A\u062F \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631.",
        "Select at least one character set."
      );
    }
    const combined = validPools.join("");
    const chars = [];
    for (const pool of validPools) {
      if (chars.length < safeLen) {
        chars.push(pool[randomInt(pool.length)]);
      }
    }
    while (chars.length < safeLen) {
      chars.push(combined[randomInt(combined.length)]);
    }
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      const tmp = chars[i];
      chars[i] = chars[j];
      chars[j] = tmp;
    }
    return chars.join("");
  }
  function generatePassphrase({
    wordCount = 6,
    separator = "-",
    capitalize = true,
    includeNumber = true
  } = {}) {
    const count = Math.min(12, Math.max(4, Math.floor(wordCount)));
    const words = [];
    for (let i = 0; i < count; i++) {
      let w = PASSPHRASE_WORDS[randomInt(PASSPHRASE_WORDS.length)];
      if (capitalize) w = w[0].toUpperCase() + w.slice(1);
      words.push(w);
    }
    if (includeNumber) {
      const numIdx = randomInt(count);
      words[numIdx] += String(randomInt(90) + 10);
    }
    return words.join(separator);
  }
  function evaluatePasswordStrength(password) {
    const pwd = String(password || "");
    const len = Array.from(pwd).length;
    if (len === 0) {
      return {
        score: 0,
        entropyBits: 0,
        labelAr: "\u0641\u0627\u0631\u063A\u0629",
        labelEn: "Empty",
        feedbackAr: "\u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631.",
        feedbackEn: "Enter a password."
      };
    }
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9\s]/.test(pwd)) pool += 32;
    if (/\s/.test(pwd)) pool += 1;
    if (/[\u0600-\u06FF]/.test(pwd)) pool += 36;
    const uniqueChars = new Set(Array.from(pwd)).size;
    const uniquenessRatio = uniqueChars / len;
    let entropy = len * Math.log2(Math.max(2, pool));
    if (uniquenessRatio < 0.5) entropy *= 0.65;
    if (/(.)\1{2,}/.test(pwd)) entropy -= 12;
    if (/(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwerty|asdf|password|admin|khazna)/i.test(pwd)) {
      entropy -= 24;
    }
    if (/^\d+$/.test(pwd)) entropy = Math.min(entropy, len * 2.5);
    const entropyBits = Math.max(0, Math.round(entropy));
    let score;
    if (len < 8 || entropyBits < 30) score = 0;
    else if (len < 10 || entropyBits < 48) score = 1;
    else if (entropyBits < 68) score = 2;
    else if (entropyBits < 88) score = 3;
    else score = 4;
    const labels = [
      { ar: "\u0636\u0639\u064A\u0641\u0629 \u062C\u062F\u0627\u064B", en: "Very weak", fbAr: "\u0642\u0635\u064A\u0631\u0629 \u062C\u062F\u0627\u064B \u0623\u0648 \u064A\u0633\u0647\u0644 \u062A\u062E\u0645\u064A\u0646\u0647\u0627.", fbEn: "Too short or predictable." },
      { ar: "\u0636\u0639\u064A\u0641\u0629", en: "Weak", fbAr: "\u0632\u0650\u062F \u0627\u0644\u0637\u0648\u0644 \u0648\u0646\u0648\u0651\u0639 \u0628\u064A\u0646 \u0627\u0644\u0623\u062D\u0631\u0641 \u0648\u0627\u0644\u0623\u0631\u0642\u0627\u0645 \u0648\u0627\u0644\u0631\u0645\u0648\u0632.", fbEn: "Increase length and mix character types." },
      { ar: "\u0645\u062A\u0648\u0633\u0637\u0629", en: "Fair", fbAr: "\u0645\u0642\u0628\u0648\u0644\u0629\u060C \u0648\u064A\u064F\u0641\u0636\u0651\u0644 \u0632\u064A\u0627\u062F\u062A\u0647\u0627 \u0625\u0644\u0649 \u0661\u0664 \u062D\u0631\u0641\u0627\u064B \u0641\u0623\u0643\u062B\u0631.", fbEn: "Decent, aim for 14+ characters." },
      { ar: "\u0642\u0648\u064A\u0629", en: "Strong", fbAr: "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u062C\u064A\u062F\u0629 \u0648\u0645\u0642\u0627\u0648\u0645\u0629 \u0644\u0644\u062A\u062E\u0645\u064A\u0646.", fbEn: "Strong password." },
      { ar: "\u0642\u0648\u064A\u0629 \u062C\u062F\u0627\u064B", en: "Very strong", fbAr: "\u0645\u0645\u062A\u0627\u0632\u0629 \u0648\u0639\u0627\u0644\u064A\u0629 \u0627\u0644\u0625\u0646\u062A\u0631\u0648\u0628\u064A\u0627.", fbEn: "Excellent high-entropy password." }
    ];
    const meta = labels[score];
    return {
      score,
      entropyBits,
      labelAr: meta.ar,
      labelEn: meta.en,
      feedbackAr: meta.fbAr,
      feedbackEn: meta.fbEn
    };
  }
  var DEFAULT_FALLBACK_KDF_SPEC = Object.freeze({
    kdf: KDF_ALGO.PBKDF2_SHA256,
    params: { iterations: 6e5 }
  });

  // src/auth/webauthn.js
  var CONVENIENCE_MAX_AGE_MS = 24 * 60 * 60 * 1e3;
  var convenienceRamState = null;
  function isWebAuthnSupported(env = globalThis) {
    return Boolean(
      env.PublicKeyCredential && env.navigator?.credentials && typeof env.navigator.credentials.create === "function" && typeof env.navigator.credentials.get === "function"
    );
  }
  function normalizeWebAuthnError(err) {
    if (err instanceof KhaznaError) return err;
    const name = err?.name || "";
    if (name === "NotAllowedError" || name === "AbortError") {
      return new KhaznaError(
        "WEBAUTHN_CANCELLED",
        "\u062A\u0645 \u0625\u0644\u063A\u0627\u0621 \u0627\u0644\u062A\u062D\u0642\u0642 \u0628\u0627\u0644\u0628\u0635\u0645\u0629 \u0623\u0648 \u0627\u0646\u062A\u0647\u062A \u0645\u0647\u0644\u0629 \u0627\u0644\u0637\u0644\u0628.",
        "Biometric verification was cancelled or timed out.",
        err
      );
    }
    if (name === "SecurityError") {
      return new KhaznaError(
        "WEBAUTHN_HTTPS_REQUIRED",
        "\u064A\u062A\u0637\u0644\u0628 \u0641\u062A\u062D \u0627\u0644\u0628\u0635\u0645\u0629 \u062A\u0634\u063A\u064A\u0644 \u062E\u0632\u0646\u0629 \u0639\u0628\u0631 \u0627\u062A\u0635\u0627\u0644 HTTPS \u0622\u0645\u0646.",
        "WebAuthn requires a secure HTTPS origin.",
        err
      );
    }
    if (name === "InvalidStateError") {
      return new KhaznaError(
        "WEBAUTHN_ALREADY_REGISTERED",
        "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0628\u0635\u0645\u0629 \u0645\u0633\u062C\u0651\u0644\u0629 \u0628\u0627\u0644\u0641\u0639\u0644 \u0639\u0644\u0649 \u0647\u0630\u0627 \u0627\u0644\u062C\u0647\u0627\u0632.",
        "Authenticator credential already registered.",
        err
      );
    }
    return new KhaznaError(
      "WEBAUTHN_ERROR",
      "\u062A\u0639\u0630\u0651\u0631 \u0625\u062A\u0645\u0627\u0645 \u0639\u0645\u0644\u064A\u0629 \u0627\u0644\u0628\u0635\u0645\u0629 \u0639\u0644\u0649 \u0647\u0630\u0627 \u0627\u0644\u062C\u0647\u0627\u0632.",
      err?.message || "WebAuthn operation failed.",
      err
    );
  }
  function extractPrfFirstBytes(cred) {
    const ext = typeof cred?.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : null;
    const first = ext?.prf?.results?.first;
    if (!first) return null;
    const bytes = first instanceof Uint8Array ? new Uint8Array(first) : ArrayBuffer.isView(first) ? new Uint8Array(first.buffer.slice(first.byteOffset, first.byteOffset + first.byteLength)) : first instanceof ArrayBuffer ? new Uint8Array(first.slice(0)) : null;
    return bytes && bytes.length >= 32 ? bytes.subarray(0, 32) : null;
  }
  function extractAttestationPublicKey(response) {
    try {
      const spkiBuf = typeof response?.getPublicKey === "function" ? response.getPublicKey() : null;
      const alg = typeof response?.getPublicKeyAlgorithm === "function" ? response.getPublicKeyAlgorithm() : -7;
      if (!spkiBuf) return null;
      return {
        spkiB64: bytesToBase64(new Uint8Array(spkiBuf)),
        alg
      };
    } catch {
      return null;
    }
  }
  function derEcdsaToP1363(der) {
    if (der.length === 64) return der;
    if (der[0] !== 48) throw new Error("Invalid DER signature sequence");
    let offset = 2;
    if (der[1] & 128) {
      offset = 2 + (der[1] & 127);
    }
    if (der[offset] !== 2) throw new Error("Invalid DER r integer");
    const rLen = der[offset + 1];
    const rBytes = der.subarray(offset + 2, offset + 2 + rLen);
    offset += 2 + rLen;
    if (der[offset] !== 2) throw new Error("Invalid DER s integer");
    const sLen = der[offset + 1];
    const sBytes = der.subarray(offset + 2, offset + 2 + sLen);
    const out = new Uint8Array(64);
    const rClean = rBytes.length > 32 ? rBytes.subarray(rBytes.length - 32) : rBytes;
    const sClean = sBytes.length > 32 ? sBytes.subarray(sBytes.length - 32) : sBytes;
    out.set(rClean, 32 - rClean.length);
    out.set(sClean, 64 - sClean.length);
    return out;
  }
  async function verifyWebAuthnAssertion({
    assertion,
    expectedChallenge,
    expectedOrigin,
    publicKeySpkiB64,
    publicKeyAlg = -7
  }) {
    const resp = assertion?.response;
    if (!resp?.clientDataJSON || !resp?.authenticatorData || !resp?.signature) {
      throw new KhaznaError(
        "WEBAUTHN_INVALID_ASSERTION",
        "\u0627\u0633\u062A\u062C\u0627\u0628\u0629 \u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0645\u0643\u062A\u0645\u0644\u0629.",
        "Incomplete WebAuthn assertion response."
      );
    }
    const clientDataBytes = new Uint8Array(resp.clientDataJSON);
    const authDataBytes = new Uint8Array(resp.authenticatorData);
    const sigBytes = new Uint8Array(resp.signature);
    const clientData = JSON.parse(utf8Decode(clientDataBytes));
    if (clientData.type !== "webauthn.get") {
      throw new KhaznaError("WEBAUTHN_INVALID_TYPE", "\u0646\u0648\u0639 \u062A\u062D\u0642\u0642 \u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D.", "Invalid WebAuthn ceremony type.");
    }
    const expectedChallengeB64Url = bytesToBase64Url(expectedChallenge);
    if (clientData.challenge !== expectedChallengeB64Url) {
      throw new KhaznaError("WEBAUTHN_CHALLENGE_MISMATCH", "\u0641\u0634\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0631\u0645\u0632 \u0627\u0644\u062A\u062D\u062F\u064A \u0644\u0644\u0628\u0635\u0645\u0629.", "WebAuthn challenge mismatch.");
    }
    if (expectedOrigin && clientData.origin !== expectedOrigin) {
      throw new KhaznaError("WEBAUTHN_ORIGIN_MISMATCH", "\u0646\u0637\u0627\u0642 \u0627\u0644\u062A\u062D\u0642\u0642 \u0628\u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0645\u062A\u0637\u0627\u0628\u0642.", "WebAuthn origin mismatch.");
    }
    if (authDataBytes.length < 37) {
      throw new KhaznaError("WEBAUTHN_BAD_AUTHDATA", "\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u0635\u0627\u062F\u0642 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D\u0629.", "Truncated authenticatorData.");
    }
    const flags = authDataBytes[32];
    if ((flags & 5) !== 5) {
      throw new KhaznaError(
        "WEBAUTHN_UV_REQUIRED",
        "\u0644\u0645 \u064A\u0643\u062A\u0645\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0627\u0644\u062D\u064A\u0648\u064A (\u0627\u0644\u0628\u0635\u0645\u0629/\u0627\u0644\u0648\u062C\u0647) \u0627\u0644\u0645\u0637\u0644\u0648\u0628.",
        "User Presence and User Verification flags are required."
      );
    }
    if (publicKeySpkiB64) {
      const clientDataHash = await sha256Bytes(clientDataBytes);
      const signedData = concatBytes(authDataBytes, clientDataHash);
      const spki = base64ToBytes(publicKeySpkiB64);
      let keyAlg;
      let verifyAlg;
      let finalSig = sigBytes;
      if (publicKeyAlg === -7) {
        keyAlg = { name: "ECDSA", namedCurve: "P-256" };
        verifyAlg = { name: "ECDSA", hash: "SHA-256" };
        finalSig = derEcdsaToP1363(sigBytes);
      } else if (publicKeyAlg === -257) {
        keyAlg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
        verifyAlg = { name: "RSASSA-PKCS1-v1_5" };
      } else {
        throw new KhaznaError(
          "WEBAUTHN_UNSUPPORTED_ALG",
          "\u062E\u0648\u0627\u0631\u0632\u0645\u064A\u0629 \u062A\u0648\u0642\u064A\u0639 \u0627\u0644\u0645\u0635\u0627\u062F\u0642 \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645\u0629.",
          `Unsupported WebAuthn public key algorithm: ${publicKeyAlg}`
        );
      }
      const pubKey = await globalThis.crypto.subtle.importKey("spki", spki, keyAlg, false, ["verify"]);
      const ok = await globalThis.crypto.subtle.verify(verifyAlg, pubKey, finalSig, signedData);
      if (!ok) {
        throw new KhaznaError(
          "WEBAUTHN_SIGNATURE_INVALID",
          "\u0641\u0634\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0627\u0644\u062A\u0634\u0641\u064A\u0631\u064A \u0645\u0646 \u062A\u0648\u0642\u064A\u0639 \u0627\u0644\u0628\u0635\u0645\u0629.",
          "WebAuthn assertion signature verification failed."
        );
      }
    }
    return true;
  }
  async function enrollBiometric({
    header,
    extractableDek,
    rpId,
    rpName = "Khazna (\u062E\u0632\u0646\u0629)",
    env = globalThis
  }) {
    if (!isWebAuthnSupported(env)) {
      throw new KhaznaError(
        "WEBAUTHN_UNSUPPORTED",
        "\u0647\u0630\u0627 \u0627\u0644\u0645\u062A\u0635\u0641\u062D \u0644\u0627 \u064A\u062F\u0639\u0645 WebAuthn \u0644\u0641\u062A\u062D \u0627\u0644\u062E\u0632\u0646\u0629 \u0628\u0627\u0644\u0628\u0635\u0645\u0629.",
        "WebAuthn is not supported in this browser."
      );
    }
    const effectiveRpId = rpId || env.location?.hostname || "localhost";
    const challenge = randomBytes(32);
    const prfSalt = randomBytes(32);
    const userId = utf8Encode(header.vaultId).subarray(0, 32);
    let cred;
    try {
      cred = await env.navigator.credentials.create({
        publicKey: {
          rp: { id: effectiveRpId, name: rpName },
          user: {
            id: userId,
            name: "khazna-local-vault",
            displayName: "Khazna Vault"
          },
          challenge,
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
          ],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required",
            residentKey: "preferred"
          },
          attestation: "none",
          timeout: 6e4,
          extensions: {
            prf: {
              eval: { first: prfSalt }
            }
          }
        }
      });
    } catch (err) {
      throw normalizeWebAuthnError(err);
    }
    if (!cred || !cred.rawId) {
      throw new KhaznaError(
        "WEBAUTHN_CREATE_FAILED",
        "\u0644\u0645 \u064A\u064F\u0639\u0650\u062F \u0627\u0644\u062C\u0647\u0627\u0632 \u0628\u064A\u0627\u0646\u0627\u062A \u0645\u0635\u0627\u062F\u0642\u0629 \u0635\u0627\u0644\u062D\u0629.",
        "WebAuthn credential creation returned empty result."
      );
    }
    const credentialId = bytesToBase64Url(new Uint8Array(cred.rawId));
    const prfSaltB64 = bytesToBase64(prfSalt);
    const pubKeyInfo = extractAttestationPublicKey(cred.response);
    let prfOutput = extractPrfFirstBytes(cred);
    if (!prfOutput) {
      const ext = typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : null;
      const shouldProbeGet = ext?.prf?.enabled !== false;
      if (shouldProbeGet) {
        try {
          const probeAssertion = await env.navigator.credentials.get({
            publicKey: {
              rpId: effectiveRpId,
              challenge: randomBytes(32),
              allowCredentials: [
                {
                  type: "public-key",
                  id: base64UrlToBytes(credentialId),
                  transports: ["internal"]
                }
              ],
              userVerification: "required",
              timeout: 6e4,
              extensions: {
                prf: {
                  eval: { first: prfSalt }
                }
              }
            }
          });
          prfOutput = extractPrfFirstBytes(probeAssertion);
        } catch {
          prfOutput = null;
        }
      }
    }
    if (prfOutput) {
      try {
        const wrapper = await createWebAuthnPrfWrapper(header, extractableDek, prfOutput, {
          credentialId,
          prfSaltB64
        });
        return {
          mode: "prf",
          wrapper
        };
      } finally {
        zeroize(prfOutput);
      }
    }
    return {
      mode: "prf-unavailable",
      pendingConvenience: {
        mode: "convenience",
        credentialId,
        publicKeySpki: pubKeyInfo?.spkiB64 || null,
        publicKeyAlg: pubKeyInfo?.alg ?? -7,
        createdAt: (/* @__PURE__ */ new Date()).toISOString()
      },
      warningAr: '\u062C\u0647\u0627\u0632\u0643 \u0623\u0648 \u0645\u062A\u0635\u0641\u062D\u0643 \u0644\u0627 \u064A\u062F\u0639\u0645 \u0627\u0645\u062A\u062F\u0627\u062F WebAuthn PRF \u0644\u0644\u062A\u0634\u0641\u064A\u0631 \u0627\u0644\u0645\u0631\u062A\u0628\u0637 \u0645\u0628\u0627\u0634\u0631\u0629 \u0628\u0627\u0644\u0628\u0635\u0645\u0629. \u064A\u0645\u0643\u0646\u0643 \u062A\u0641\u0639\u064A\u0644 "\u0641\u062A\u062D \u0627\u0644\u0628\u0635\u0645\u0629 \u0627\u0644\u0633\u0631\u064A\u0639 (\u0648\u0636\u0639 \u0627\u0644\u0631\u0627\u062D\u0629)" \u0627\u0644\u0630\u064A \u064A\u062D\u062A\u0641\u0638 \u0628\u0645\u0641\u062A\u0627\u062D \u0645\u0624\u0642\u062A \u0641\u064A \u0627\u0644\u0630\u0627\u0643\u0631\u0629 \u0641\u0642\u0637\u060C \u0648\u064A\u064F\u0644\u0632\u0645\u0643 \u0628\u0625\u062F\u062E\u0627\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0628\u0639\u062F \u0643\u0644 \u0625\u0639\u0627\u062F\u0629 \u062A\u0634\u063A\u064A\u0644 \u0644\u0644\u062A\u0637\u0628\u064A\u0642 \u0648\u0643\u0644 \u0662\u0664 \u0633\u0627\u0639\u0629\u060C \u0648\u064A\u0645\u0643\u0646\u0643 \u062A\u0639\u0637\u064A\u0644\u0647 \u0641\u064A \u0623\u064A \u0648\u0642\u062A.',
      warningEn: 'Your device/browser does not support the WebAuthn PRF extension for cryptographically bound biometric wrapping. You may enable "Convenience Biometric Unlock", which keeps an ephemeral wrapper in RAM only, still demands your Master Password after every cold start and every 24 hours, and can be disabled anytime.'
    };
  }
  async function armConvenienceRamSession(vaultId, extractableDek, masterUnlockedAt = Date.now()) {
    clearConvenienceRamSession();
    const ephemKey = await globalThis.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
    const iv = randomBytes(12);
    const wrapped = await globalThis.crypto.subtle.wrapKey(
      "raw",
      extractableDek,
      ephemKey,
      { name: "AES-GCM", iv }
    );
    convenienceRamState = {
      vaultId,
      ephemKey,
      iv,
      wrappedDek: new Uint8Array(wrapped),
      armedAt: masterUnlockedAt
    };
  }
  function clearConvenienceRamSession() {
    if (convenienceRamState) {
      zeroize(convenienceRamState.iv, convenienceRamState.wrappedDek);
      convenienceRamState = null;
    }
  }
  function getConvenienceStatus(header, now = Date.now()) {
    const wa = header?.wrappers?.webauthn;
    if (!wa || wa.mode !== "convenience") {
      return { enabled: false, ready: false, reason: "disabled" };
    }
    if (!convenienceRamState || convenienceRamState.vaultId !== header.vaultId) {
      return { enabled: true, ready: false, reason: "cold-start" };
    }
    const age = now - convenienceRamState.armedAt;
    if (age >= CONVENIENCE_MAX_AGE_MS || age < 0) {
      clearConvenienceRamSession();
      return { enabled: true, ready: false, reason: "expired-24h" };
    }
    return {
      enabled: true,
      ready: true,
      reason: "ready",
      remainingMs: CONVENIENCE_MAX_AGE_MS - age
    };
  }
  async function unlockWithBiometric(header, opts = {}) {
    const env = opts.env || globalThis;
    const wa = header?.wrappers?.webauthn;
    if (!wa || !wa.credentialId) {
      throw new KhaznaError(
        "BIOMETRIC_NOT_ENABLED",
        "\u0641\u062A\u062D \u0627\u0644\u062E\u0632\u0646\u0629 \u0628\u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0645\u0641\u0639\u0651\u0644 \u0641\u064A \u0627\u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A.",
        "Biometric unlock is not enabled."
      );
    }
    if (!isWebAuthnSupported(env)) {
      throw new KhaznaError(
        "WEBAUTHN_UNSUPPORTED",
        "\u0647\u0630\u0627 \u0627\u0644\u0645\u062A\u0635\u0641\u062D \u0644\u0627 \u064A\u062F\u0639\u0645 WebAuthn.",
        "WebAuthn is not supported in this browser."
      );
    }
    const effectiveRpId = opts.rpId || env.location?.hostname || "localhost";
    const challenge = randomBytes(32);
    if (wa.mode === "prf") {
      const prfSalt = base64ToBytes(wa.prfSalt);
      let assertion;
      try {
        assertion = await env.navigator.credentials.get({
          publicKey: {
            rpId: effectiveRpId,
            challenge,
            allowCredentials: [
              {
                type: "public-key",
                id: base64UrlToBytes(wa.credentialId),
                transports: ["internal"]
              }
            ],
            userVerification: "required",
            timeout: 6e4,
            extensions: {
              prf: {
                eval: { first: prfSalt }
              }
            }
          }
        });
      } catch (err) {
        throw normalizeWebAuthnError(err);
      }
      const prfOutput = extractPrfFirstBytes(assertion);
      if (!prfOutput) {
        throw new KhaznaError(
          "WEBAUTHN_PRF_MISSING",
          "\u0644\u0645 \u064A\u064F\u0639\u0650\u062F \u0627\u0644\u062C\u0647\u0627\u0632 \u0645\u0641\u062A\u0627\u062D PRF \u0645\u0646 \u0627\u0644\u0628\u0635\u0645\u0629 \u2014 \u064A\u064F\u0631\u062C\u0649 \u0627\u0644\u0641\u062A\u062D \u0628\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629.",
          "Authenticator did not return PRF output. Unlock with Master Password."
        );
      }
      try {
        const dek = await unwrapDekWithWebAuthnPrf(header, prfOutput, { extractable: false });
        return { dek, mode: "prf" };
      } finally {
        zeroize(prfOutput);
      }
    }
    if (wa.mode === "convenience") {
      const status = getConvenienceStatus(header, opts.now ?? Date.now());
      if (!status.ready) {
        const arMsg = status.reason === "expired-24h" ? "\u0627\u0646\u062A\u0647\u062A \u0645\u0647\u0644\u0629 \u0662\u0664 \u0633\u0627\u0639\u0629 \u0644\u0648\u0636\u0639 \u0627\u0644\u0628\u0635\u0645\u0629 \u0627\u0644\u0633\u0631\u064A\u0639 \u2014 \u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0644\u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u0641\u0639\u064A\u0644." : "\u062A\u0645\u062A \u0625\u0639\u0627\u062F\u0629 \u062A\u0634\u063A\u064A\u0644 \u0627\u0644\u062A\u0637\u0628\u064A\u0642 \u2014 \u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0623\u0648\u0644\u0627\u064B (\u0648\u0636\u0639 \u0627\u0644\u0628\u0635\u0645\u0629 \u0627\u0644\u0633\u0631\u064A\u0639 \u0645\u0624\u0642\u062A \u0641\u064A \u0627\u0644\u0630\u0627\u0643\u0631\u0629 \u0641\u0642\u0637).";
        const enMsg = status.reason === "expired-24h" ? "24-hour window expired for Convenience Biometric Unlock \u2014 enter Master Password." : "Cold start detected \u2014 Master Password is required (Convenience Unlock is RAM-only).";
        throw new KhaznaError("CONVENIENCE_MASTER_REQUIRED", arMsg, enMsg);
      }
      let assertion;
      try {
        assertion = await env.navigator.credentials.get({
          publicKey: {
            rpId: effectiveRpId,
            challenge,
            allowCredentials: [
              {
                type: "public-key",
                id: base64UrlToBytes(wa.credentialId),
                transports: ["internal"]
              }
            ],
            userVerification: "required",
            timeout: 6e4
          }
        });
      } catch (err) {
        throw normalizeWebAuthnError(err);
      }
      await verifyWebAuthnAssertion({
        assertion,
        expectedChallenge: challenge,
        expectedOrigin: opts.expectedOrigin ?? env.location?.origin,
        publicKeySpkiB64: wa.publicKeySpki,
        publicKeyAlg: wa.publicKeyAlg ?? -7
      });
      const dek = await globalThis.crypto.subtle.unwrapKey(
        "raw",
        convenienceRamState.wrappedDek,
        convenienceRamState.ephemKey,
        { name: "AES-GCM", iv: convenienceRamState.iv },
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
      return { dek, mode: "convenience" };
    }
    throw new KhaznaError("INVALID_BIOMETRIC_MODE", "\u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0645\u0639\u0631\u0648\u0641\u0629.", "Unknown biometric wrapper mode.");
  }
  async function verifyBiometricForReauth(header, opts = {}) {
    const env = opts.env || globalThis;
    const wa = header?.wrappers?.webauthn;
    if (!wa?.credentialId || !isWebAuthnSupported(env)) {
      throw new KhaznaError(
        "BIOMETRIC_NOT_AVAILABLE",
        "\u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0645\u0641\u0639\u0651\u0644\u0629 \u2014 \u0627\u0633\u062A\u062E\u062F\u0645 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629.",
        "Biometric re-authentication unavailable."
      );
    }
    const effectiveRpId = opts.rpId || env.location?.hostname || "localhost";
    const challenge = randomBytes(32);
    let assertion;
    try {
      assertion = await env.navigator.credentials.get({
        publicKey: {
          rpId: effectiveRpId,
          challenge,
          allowCredentials: [
            {
              type: "public-key",
              id: base64UrlToBytes(wa.credentialId),
              transports: ["internal"]
            }
          ],
          userVerification: "required",
          timeout: 6e4
        }
      });
    } catch (err) {
      throw normalizeWebAuthnError(err);
    }
    await verifyWebAuthnAssertion({
      assertion,
      expectedChallenge: challenge,
      expectedOrigin: opts.expectedOrigin ?? env.location?.origin,
      publicKeySpkiB64: wa.publicKeySpki || null,
      publicKeyAlg: wa.publicKeyAlg ?? -7
    });
    return true;
  }

  // src/auth/session.js
  function getNativeBiometricPlugin(env = globalThis) {
    try {
      if (env.Capacitor?.Plugins?.NativeBiometric) {
        return env.Capacitor.Plugins.NativeBiometric;
      }
    } catch {
    }
    return null;
  }
  var BACKOFF_SCHEDULE_SEC = Object.freeze([0, 0, 0, 5, 15, 30, 60, 120, 300, 600]);
  function computeBackoffMs(failedAttempts) {
    if (failedAttempts <= 0) return 0;
    const idx = Math.min(failedAttempts - 1, BACKOFF_SCHEDULE_SEC.length - 1);
    return BACKOFF_SCHEDULE_SEC[idx] * 1e3;
  }
  var DEFAULT_SECTIONS = Object.freeze([
    { nameAr: "\u0639\u0627\u0645", nameEn: "General", emoji: "\u{1F510}", color: "#38bdf8" },
    { nameAr: "\u0627\u0644\u0628\u0646\u0648\u0643 \u0648\u0627\u0644\u0645\u0627\u0644", nameEn: "Banking", emoji: "\u{1F3E6}", color: "#10b981" },
    { nameAr: "\u0627\u0644\u062A\u0648\u0627\u0635\u0644 \u0627\u0644\u0627\u062C\u062A\u0645\u0627\u0639\u064A", nameEn: "Social", emoji: "\u{1F4AC}", color: "#a78bfa" },
    { nameAr: "\u0627\u0644\u0639\u0645\u0644", nameEn: "Work", emoji: "\u{1F4BC}", color: "#f59e0b" }
  ]);
  var ClipboardGuard = class {
    constructor(env = globalThis) {
      this._env = env;
      this._timer = null;
      this._listeners = /* @__PURE__ */ new Set();
    }
    onStatus(cb) {
      this._listeners.add(cb);
      return () => this._listeners.delete(cb);
    }
    _emit(event) {
      for (const cb of this._listeners) {
        try {
          cb(event);
        } catch {
        }
      }
    }
    async _writeClipboardRaw(value) {
      const str = String(value);
      const capClip = this._env.Capacitor?.Plugins?.Clipboard;
      if (capClip && typeof capClip.write === "function") {
        try {
          await capClip.write({ string: str });
          return;
        } catch {
        }
      }
      const clip = this._env.navigator?.clipboard;
      if (clip && typeof clip.writeText === "function") {
        try {
          await clip.writeText(str);
          return;
        } catch {
        }
      }
      const doc = this._env.document;
      if (doc && typeof doc.createElement === "function" && typeof doc.execCommand === "function") {
        const ta = doc.createElement("textarea");
        ta.className = "clipboard-fallback-ta";
        ta.setAttribute("readonly", "");
        ta.value = str;
        doc.body.appendChild(ta);
        ta.select();
        const ok = doc.execCommand("copy");
        ta.remove();
        if (ok) return;
      }
      throw new KhaznaError(
        "CLIPBOARD_UNAVAILABLE",
        "\u062A\u0639\u0630\u0651\u0631 \u0627\u0644\u0648\u0635\u0648\u0644 \u0625\u0644\u0649 \u0627\u0644\u062D\u0627\u0641\u0638\u0629 \u0641\u064A \u0647\u0630\u0627 \u0627\u0644\u0645\u062A\u0635\u0641\u062D.",
        "Clipboard API is unavailable."
      );
    }
    async copySecret(text, clearAfterSec = 30) {
      await this._writeClipboardRaw(String(text));
      if (this._timer) {
        clearTimeout(this._timer);
        this._timer = null;
      }
      if (clearAfterSec > 0) {
        const clearAt = Date.now() + clearAfterSec * 1e3;
        this._emit({ type: "copied", clearAfterSec, clearAt });
        this._timer = setTimeout(async () => {
          this._timer = null;
          try {
            const capClip = this._env.Capacitor?.Plugins?.Clipboard;
            if (!capClip && this._env.document && typeof this._env.document.hasFocus === "function" && !this._env.document.hasFocus()) {
              this._emit({ type: "clear-skipped-unfocused" });
              return;
            }
            await this._writeClipboardRaw("");
            this._emit({ type: "cleared" });
          } catch {
            this._emit({ type: "clear-failed" });
          }
        }, clearAfterSec * 1e3);
      } else {
        this._emit({ type: "copied", clearAfterSec: 0, clearAt: 0 });
      }
    }
    cancel() {
      if (this._timer) {
        clearTimeout(this._timer);
        this._timer = null;
      }
    }
  };
  var VaultSession = class {
    /** @type {CryptoKey|null} Strictly private non-extractable DEK */
    #dek = null;
    constructor({ storage: storage2, nowFn = () => Date.now(), env = globalThis, useWorker = true }) {
      this.storage = storage2;
      this._now = nowFn;
      this._env = env;
      this._useWorker = useWorker;
      this._header = null;
      this._settings = null;
      this._unlockedAt = 0;
      this._lastActivityAt = 0;
      this._inactivityTimer = null;
      this._bgTimer = null;
      this._blurred = false;
      this._listeners = /* @__PURE__ */ new Set();
      this.clipboard = new ClipboardGuard(env);
      this._unsubSync = this.storage.onSyncEvent((msg) => {
        if (msg.type === "VAULT_LOCKED") {
          this.lock({ broadcast: false, reason: "cross-tab" });
        } else if (msg.type === "VAULT_WIPED") {
          clearConvenienceRamSession();
          this.lock({ broadcast: false, reason: "wiped" });
          this._header = null;
          this._emit("wiped", {});
        } else if (msg.type === "VAULT_UPDATED") {
          this.refreshMeta().then(() => this._emit("sync-updated", msg.detail));
        }
      });
    }
    on(listener) {
      this._listeners.add(listener);
      return () => this._listeners.delete(listener);
    }
    _emit(type, payload = {}) {
      for (const cb of this._listeners) {
        try {
          cb({ type, ...payload });
        } catch {
        }
      }
    }
    get isUnlocked() {
      return this.#dek !== null && this._header !== null;
    }
    get hasVault() {
      return Boolean(this._header && this._header.vaultId);
    }
    get header() {
      return this._header;
    }
    get settings() {
      return this._settings;
    }
    get vaultId() {
      return this._header?.vaultId || null;
    }
    get isBlurred() {
      return this._blurred;
    }
    async init() {
      await this.refreshMeta();
      return {
        hasVault: this.hasVault,
        settings: this._settings,
        header: this._header
      };
    }
    async refreshMeta() {
      this._header = await this.storage.getHeader();
      this._settings = await this.storage.getSettings();
    }
    getLockoutRemainingMs() {
      const until = this._header?.security?.lockoutUntil || 0;
      return Math.max(0, until - this._now());
    }
    getBiometricState() {
      const nativePlugin = getNativeBiometricPlugin(this._env);
      if (nativePlugin) {
        const nativeWrap = this._header?.wrappers?.nativeBiometric;
        if (nativeWrap?.enabled) {
          return { enabled: true, mode: "native", ready: true, reason: "native-ready" };
        }
        return { enabled: false, mode: "native", ready: false, reason: "disabled" };
      }
      const wa = this._header?.wrappers?.webauthn;
      if (!wa) return { enabled: false, mode: null, ready: false, reason: "disabled" };
      if (wa.mode === "prf") {
        return { enabled: true, mode: "prf", ready: true, reason: "prf-ready" };
      }
      const conv = getConvenienceStatus(this._header, this._now());
      return { enabled: true, mode: "convenience", ready: conv.ready, reason: conv.reason, remainingMs: conv.remainingMs || 0 };
    }
    _assertUnlocked() {
      if (!this.#dek || !this._header) {
        throw new KhaznaError("VAULT_LOCKED", "\u0627\u0644\u062E\u0632\u0646\u0629 \u0645\u0642\u0641\u0644\u0629 \u062D\u0627\u0644\u064A\u0627\u064B.", "Vault is locked.");
      }
    }
    _assertNotLockedOut() {
      const rem = this.getLockoutRemainingMs();
      if (rem > 0) {
        const secs = Math.ceil(rem / 1e3);
        throw new KhaznaError(
          "LOCKED_OUT",
          `\u062A\u0645 \u062A\u0642\u064A\u064A\u062F \u0627\u0644\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0645\u0624\u0642\u062A\u0627\u064B \u0644\u0623\u0645\u0627\u0646\u0643. \u062D\u0627\u0648\u0644 \u0645\u062C\u062F\u062F\u0627\u064B \u0628\u0639\u062F ${secs} \u062B\u0627\u0646\u064A\u0629.`,
          `Too many failed attempts. Please wait ${secs} seconds.`
        );
      }
    }
    async _recordFailedAttempt() {
      if (!this._header) return;
      const prev = this._header.security || {};
      const failedAttempts = (prev.failedAttempts || 0) + 1;
      const wipeLimit = prev.wipeAfterFailures || 0;
      if (wipeLimit > 0 && failedAttempts >= wipeLimit) {
        const nativePlugin = getNativeBiometricPlugin(this._env);
        if (nativePlugin && this._header?.vaultId) {
          try {
            await nativePlugin.deleteSecret({ key: `khazna_vault_${this._header.vaultId}` });
          } catch {
          }
        }
        clearConvenienceRamSession();
        this.#dek = null;
        await this.storage.wipeAll({ wipeSettings: false });
        this._header = null;
        this._emit("wiped", { reason: "max-failures" });
        throw new KhaznaError(
          "VAULT_WIPED_AFTER_FAILURES",
          `\u062A\u0645 \u0645\u0633\u062D \u0627\u0644\u062E\u0632\u0646\u0629 \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0628\u0639\u062F ${failedAttempts} \u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0641\u0627\u0634\u0644\u0629 \u0645\u062A\u062A\u0627\u0644\u064A\u0629 \u0648\u0641\u0642\u0627\u064B \u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0644\u0623\u0645\u0627\u0646.`,
          `Vault was automatically wiped after ${failedAttempts} consecutive failed attempts.`
        );
      }
      const backoffMs = computeBackoffMs(failedAttempts);
      const lockoutUntil = backoffMs > 0 ? this._now() + backoffMs : 0;
      const updatedHeader = {
        ...this._header,
        security: {
          ...prev,
          failedAttempts,
          lockoutUntil
        }
      };
      this._header = updatedHeader;
      await this.storage.saveHeader(updatedHeader);
      this._emit("failed-attempt", { failedAttempts, lockoutUntil, backoffMs });
    }
    async _resetFailedAttempts(markMasterUnlock = false) {
      if (!this._header) return;
      const prev = this._header.security || {};
      const needsSave = (prev.failedAttempts || 0) > 0 || (prev.lockoutUntil || 0) > 0 || markMasterUnlock;
      if (!needsSave) return;
      const updatedHeader = {
        ...this._header,
        security: {
          ...prev,
          failedAttempts: 0,
          lockoutUntil: 0,
          lastMasterUnlockAt: markMasterUnlock ? this._now() : prev.lastMasterUnlockAt || this._now()
        }
      };
      this._header = updatedHeader;
      await this.storage.saveHeader(updatedHeader);
    }
    /**
     * Creates a new vault with calibrated Argon2id (or provided kdfSpec), default encrypted sections,
     * and returns the one-time 14-group Base32 Recovery Key.
     */
    async createVault({ masterPassword, kdfSpec = null, enforceMinimums = true, seedDefaultSections = true }) {
      const spec = kdfSpec || await calibrateKdf({ useWorker: this._useWorker });
      const { header, dek, recoveryKeyFormatted, kdfEngine } = await createVaultCrypto({
        masterPassword,
        kdfSpec: { kdf: spec.kdf, params: spec.params },
        enforceMinimums,
        useWorker: this._useWorker
      });
      await this.storage.saveHeader(header);
      this._header = header;
      this.#dek = dek;
      this._unlockedAt = this._now();
      this._lastActivityAt = this._now();
      if (seedDefaultSections) {
        const lang = this._settings?.lang || "ar";
        const envelopes = [];
        for (let i = 0; i < DEFAULT_SECTIONS.length; i++) {
          const s = DEFAULT_SECTIONS[i];
          envelopes.push(await encryptRecord(this.#dek, {
            id: randomId("sec"),
            type: "section",
            vaultId: header.vaultId,
            data: {
              name: lang === "en" ? s.nameEn : s.nameAr,
              emoji: s.emoji,
              color: s.color,
              order: i
            }
          }));
        }
        await this.storage.putRecordsBatch(envelopes);
      }
      this._settings = await this.storage.saveSettings({ onboardingDone: true });
      this._scheduleInactivityLock();
      this._emit("unlocked", { method: "create", kdfEngine });
      return {
        header,
        recoveryKeyFormatted,
        kdfEngine
      };
    }
    /**
     * Unlocks the vault using the Master Password.
     */
    async unlockWithPassword(masterPassword) {
      await this.refreshMeta();
      if (!this._header) {
        throw new KhaznaError("NO_VAULT", "\u0644\u0627 \u062A\u0648\u062C\u062F \u062E\u0632\u0646\u0629 \u0645\u0647\u064A\u0651\u0623\u0629 \u0639\u0644\u0649 \u0647\u0630\u0627 \u0627\u0644\u062C\u0647\u0627\u0632.", "No vault exists.");
      }
      this._assertNotLockedOut();
      try {
        const wantConvenienceArm = this._header?.wrappers?.webauthn?.mode === "convenience";
        const { dek, kdfEngine } = await unwrapDekWithPassword(this._header, masterPassword, {
          extractable: wantConvenienceArm,
          useWorker: this._useWorker
        });
        if (wantConvenienceArm) {
          await armConvenienceRamSession(this._header.vaultId, dek, this._now());
          const strict = await unwrapDekWithPassword(this._header, masterPassword, {
            extractable: false,
            useWorker: this._useWorker
          });
          this.#dek = strict.dek;
        } else {
          this.#dek = dek;
        }
        await this._resetFailedAttempts(true);
        await this.storage.purgeExpiredTrash(30);
        this._unlockedAt = this._now();
        this._lastActivityAt = this._now();
        this._scheduleInactivityLock();
        this._emit("unlocked", { method: "password", kdfEngine });
        return { kdfEngine };
      } catch (err) {
        if (err?.code === "WRONG_PASSWORD") {
          await this._recordFailedAttempt();
        }
        throw err;
      }
    }
    /**
     * Unlocks the vault via Android Biometric (Native Android BiometricPrompt or WebAuthn PRF).
     */
    async unlockWithBiometric(opts = {}) {
      await this.refreshMeta();
      if (!this._header) {
        throw new KhaznaError("NO_VAULT", "\u0644\u0627 \u062A\u0648\u062C\u062F \u062E\u0632\u0646\u0629 \u0645\u0647\u064A\u0651\u0623\u0629.", "No vault exists.");
      }
      this._assertNotLockedOut();
      const nativePlugin = getNativeBiometricPlugin(this._env);
      if (nativePlugin && this._header?.wrappers?.nativeBiometric?.enabled) {
        const isAr = (this._settings?.lang || "ar") === "ar";
        let res;
        try {
          res = await nativePlugin.getSecret({
            key: `khazna_vault_${this._header.vaultId}`,
            title: isAr ? "\u062E\u0632\u0646\u0629 \u2014 \u0641\u062A\u062D \u0628\u0627\u0644\u0628\u0635\u0645\u0629" : "Khazna \u2014 Biometric Unlock",
            subtitle: isAr ? "\u0627\u0644\u0645\u0633 \u0645\u0633\u062A\u0634\u0639\u0631 \u0627\u0644\u0628\u0635\u0645\u0629 \u0644\u0641\u062A\u062D \u0627\u0644\u062E\u0632\u0646\u0629" : "Touch the fingerprint sensor to unlock",
            cancelText: isAr ? "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629" : "Master Password"
          });
        } catch (err) {
          const code = String(err?.code || "");
          if (code === "NOT_FOUND" || code === "KEY_INVALIDATED") {
            throw new KhaznaError(
              "BIOMETRIC_INVALIDATED",
              "\u062A\u0645 \u062A\u063A\u064A\u064A\u0631 \u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0644\u0628\u0635\u0645\u0629 \u0639\u0644\u0649 \u0627\u0644\u062C\u0647\u0627\u0632. \u0627\u0641\u062A\u062D \u0628\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u062B\u0645 \u0623\u0639\u062F \u062A\u0641\u0639\u064A\u0644 \u0627\u0644\u0628\u0635\u0645\u0629 \u0645\u0646 \u0627\u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A.",
              "Device biometric key was invalidated. Unlock with Master Password and re-enable biometrics.",
              err
            );
          }
          throw new KhaznaError("BIOMETRIC_CANCELLED", "\u062A\u0645 \u0625\u0644\u063A\u0627\u0621 \u0627\u0644\u062A\u062D\u0642\u0642 \u0628\u0627\u0644\u0628\u0635\u0645\u0629.", "Biometric authentication was cancelled.", err);
        }
        if (!res?.secret) {
          throw new KhaznaError("BIOMETRIC_FAILED", "\u0641\u0634\u0644 \u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 \u0627\u0644\u0628\u0635\u0645\u0629.", "Biometric authentication failed.");
        }
        const rawDekBytes = base64ToBytes(res.secret);
        const dek2 = await this._env.crypto.subtle.importKey(
          "raw",
          rawDekBytes,
          { name: "AES-GCM" },
          false,
          ["encrypt", "decrypt"]
        );
        zeroize(rawDekBytes);
        this.#dek = dek2;
        await this._resetFailedAttempts(false);
        await this.storage.purgeExpiredTrash(30);
        this._unlockedAt = this._now();
        this._lastActivityAt = this._now();
        this._scheduleInactivityLock();
        this._emit("unlocked", { method: "biometric-native" });
        return { mode: "native" };
      }
      const { dek, mode } = await unlockWithBiometric(this._header, {
        ...opts,
        env: opts.env || this._env,
        now: this._now()
      });
      this.#dek = dek;
      await this._resetFailedAttempts(false);
      await this.storage.purgeExpiredTrash(30);
      this._unlockedAt = this._now();
      this._lastActivityAt = this._now();
      this._scheduleInactivityLock();
      this._emit("unlocked", { method: `biometric-${mode}` });
      return { mode };
    }
    /**
     * Unlocks the vault using the 14-group Base32 Recovery Key, optionally setting a new Master Password immediately.
     */
    async unlockWithRecoveryKey(formattedRecoveryKey, newMasterPassword = null, opts = {}) {
      await this.refreshMeta();
      if (!this._header) {
        throw new KhaznaError("NO_VAULT", "\u0644\u0627 \u062A\u0648\u062C\u062F \u062E\u0632\u0646\u0629 \u0645\u0647\u064A\u0651\u0623\u0629.", "No vault exists.");
      }
      this._assertNotLockedOut();
      try {
        if (newMasterPassword) {
          const { updatedHeader, dek } = await rewrapMasterPassword({
            header: this._header,
            recoveryKey: formattedRecoveryKey,
            newMasterPassword,
            enforceMinimums: opts.enforceMinimums ?? true,
            useWorker: this._useWorker
          });
          await this.storage.atomicOperationWithSnapshot({
            reason: "recovery-password-reset",
            newHeader: updatedHeader
          });
          this._header = updatedHeader;
          this.#dek = dek;
        } else {
          const dek = await unwrapDekWithRecoveryKey(this._header, formattedRecoveryKey, {
            extractable: false
          });
          this.#dek = dek;
          await this._resetFailedAttempts(true);
        }
        await this.storage.purgeExpiredTrash(30);
        this._unlockedAt = this._now();
        this._lastActivityAt = this._now();
        this._scheduleInactivityLock();
        this._emit("unlocked", { method: "recovery" });
        return true;
      } catch (err) {
        if (err?.code === "WRONG_RECOVERY_KEY" || err?.code === "INVALID_RECOVERY_KEY_CHECKSUM" || err?.code === "INVALID_RECOVERY_KEY") {
          await this._recordFailedAttempt();
        }
        throw err;
      }
    }
    /**
     * Locks the vault immediately, drops DEK reference, cancels timers, and syncs across tabs.
     */
    lock({ broadcast = true, reason = "manual", clearConvenience = false } = {}) {
      this.#dek = null;
      this._clearTimers();
      if (clearConvenience) {
        clearConvenienceRamSession();
      }
      if (broadcast) {
        this.storage.broadcast("VAULT_LOCKED", { reason });
      }
      this._emit("locked", { reason });
    }
    /**
     * Re-authenticates the user before sensitive actions (reveal CVV/PIN, plain export,
     * change master password, wipe vault).
     */
    async verifyReauth({ masterPassword = null, useBiometric = false, env = this._env } = {}) {
      this._assertUnlocked();
      const nativePlugin = getNativeBiometricPlugin(env);
      if (useBiometric && nativePlugin && this._header?.wrappers?.nativeBiometric?.enabled) {
        const isAr = (this._settings?.lang || "ar") === "ar";
        try {
          await nativePlugin.authenticate({
            title: isAr ? "\u062E\u0632\u0646\u0629 \u2014 \u062A\u0623\u0643\u064A\u062F \u0627\u0644\u0647\u0648\u064A\u0629" : "Khazna \u2014 Confirm Identity",
            subtitle: isAr ? "\u0627\u0644\u0645\u0633 \u0645\u0633\u062A\u0634\u0639\u0631 \u0627\u0644\u0628\u0635\u0645\u0629 \u0644\u0644\u0645\u062A\u0627\u0628\u0639\u0629" : "Touch the fingerprint sensor to continue",
            cancelText: isAr ? "\u0625\u0644\u063A\u0627\u0621" : "Cancel"
          });
          return true;
        } catch (err) {
          throw new KhaznaError("BIOMETRIC_CANCELLED", "\u062A\u0645 \u0625\u0644\u063A\u0627\u0621 \u0627\u0644\u062A\u062D\u0642\u0642 \u0628\u0627\u0644\u0628\u0635\u0645\u0629.", "Biometric authentication was cancelled.", err);
        }
      }
      if (useBiometric && this._header?.wrappers?.webauthn) {
        await verifyBiometricForReauth(this._header, { env });
        return true;
      }
      if (typeof masterPassword === "string" && masterPassword.length > 0) {
        await unwrapDekWithPassword(this._header, masterPassword, {
          extractable: false,
          useWorker: this._useWorker
        });
        return true;
      }
      throw new KhaznaError(
        "REAUTH_REQUIRED",
        "\u064A\u062A\u0637\u0644\u0628 \u0647\u0630\u0627 \u0627\u0644\u0625\u062C\u0631\u0627\u0621 \u0627\u0644\u062D\u0633\u0627\u0633 \u062A\u0623\u0643\u064A\u062F \u0647\u0648\u064A\u062A\u0643 \u0628\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0623\u0648 \u0627\u0644\u0628\u0635\u0645\u0629.",
        "Re-authentication with Master Password or Biometric is required."
      );
    }
    /**
     * Enrolls biometric unlock (Native Android BiometricPrompt or WebAuthn PRF).
     */
    async enrollBiometricWithPassword(masterPassword, opts = {}) {
      this._assertUnlocked();
      const { dek: tempDek } = await unwrapDekWithPassword(this._header, masterPassword, {
        extractable: true,
        useWorker: this._useWorker
      });
      const nativePlugin = getNativeBiometricPlugin(this._env);
      if (nativePlugin) {
        const isAr = (this._settings?.lang || "ar") === "ar";
        const avail = await nativePlugin.isAvailable();
        if (!avail?.isAvailable) {
          throw new KhaznaError(
            "BIOMETRIC_UNAVAILABLE",
            "\u0627\u0644\u0628\u0635\u0645\u0629 \u063A\u064A\u0631 \u0645\u0641\u0639\u0651\u0644\u0629 \u0639\u0644\u0649 \u062C\u0647\u0627\u0632\u0643. \u0623\u0636\u0641 \u0628\u0635\u0645\u0629 \u0641\u064A \u0625\u0639\u062F\u0627\u062F\u0627\u062A \u0627\u0644\u0623\u0646\u062F\u0631\u0648\u064A\u062F \u0623\u0648\u0644\u0627\u064B \u062B\u0645 \u0623\u0639\u062F \u0627\u0644\u0645\u062D\u0627\u0648\u0644\u0629.",
            "Device biometric authentication is not available or no fingerprint is enrolled in Android Settings."
          );
        }
        try {
          await nativePlugin.authenticate({
            title: isAr ? "\u062E\u0632\u0646\u0629 \u2014 \u062A\u0641\u0639\u064A\u0644 \u0627\u0644\u0628\u0635\u0645\u0629" : "Khazna \u2014 Enable Biometric",
            subtitle: isAr ? "\u0627\u0644\u0645\u0633 \u0645\u0633\u062A\u0634\u0639\u0631 \u0627\u0644\u0628\u0635\u0645\u0629 \u0644\u062A\u0623\u0643\u064A\u062F \u0627\u0644\u062A\u0641\u0639\u064A\u0644" : "Touch the fingerprint sensor to confirm enrollment",
            cancelText: isAr ? "\u0625\u0644\u063A\u0627\u0621" : "Cancel"
          });
        } catch (err) {
          throw new KhaznaError("BIOMETRIC_CANCELLED", "\u062A\u0645 \u0625\u0644\u063A\u0627\u0621 \u062A\u0641\u0639\u064A\u0644 \u0627\u0644\u0628\u0635\u0645\u0629.", "Biometric enrollment was cancelled.", err);
        }
        const rawDekBytes = await this._env.crypto.subtle.exportKey("raw", tempDek);
        const rawArr = new Uint8Array(rawDekBytes);
        const b64Secret = bytesToBase64(rawArr);
        zeroize(rawArr);
        await nativePlugin.setSecret({
          key: `khazna_vault_${this._header.vaultId}`,
          secret: b64Secret
        });
        const updatedHeader = {
          ...this._header,
          wrappers: {
            ...this._header.wrappers,
            nativeBiometric: {
              enabled: true,
              enrolledAt: this._now()
            }
          },
          updatedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
        await this.storage.saveHeader(updatedHeader);
        this._header = updatedHeader;
        this._emit("biometric-updated", { mode: "native" });
        return { mode: "native" };
      }
      const result = await enrollBiometric({
        header: this._header,
        extractableDek: tempDek,
        rpId: opts.rpId,
        env: opts.env || this._env
      });
      if (result.mode === "prf") {
        const updatedHeader = {
          ...this._header,
          wrappers: {
            ...this._header.wrappers,
            webauthn: result.wrapper
          },
          updatedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
        await this.storage.saveHeader(updatedHeader);
        this._header = updatedHeader;
        this._emit("biometric-updated", { mode: "prf" });
        return { mode: "prf" };
      }
      return {
        ...result,
        _armConvenience: async () => {
          await armConvenienceRamSession(this._header.vaultId, tempDek, this._now());
          const updatedHeader = {
            ...this._header,
            wrappers: {
              ...this._header.wrappers,
              webauthn: result.pendingConvenience
            },
            updatedAt: (/* @__PURE__ */ new Date()).toISOString()
          };
          await this.storage.saveHeader(updatedHeader);
          this._header = updatedHeader;
          this._emit("biometric-updated", { mode: "convenience" });
          return { mode: "convenience" };
        }
      };
    }
    async disableBiometric() {
      this._assertUnlocked();
      const nativePlugin = getNativeBiometricPlugin(this._env);
      if (nativePlugin) {
        try {
          await nativePlugin.deleteSecret({ key: `khazna_vault_${this._header?.vaultId}` });
        } catch {
        }
      }
      clearConvenienceRamSession();
      const updatedHeader = {
        ...this._header,
        wrappers: {
          ...this._header.wrappers,
          webauthn: null,
          nativeBiometric: null
        },
        updatedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      await this.storage.saveHeader(updatedHeader);
      this._header = updatedHeader;
      this._emit("biometric-updated", { mode: null });
    }
    /**
     * Atomically changes Master Password (and optionally upgrades KDF parameters)
     * with a rolling encrypted snapshot created first.
     */
    async changeMasterPassword({ currentPassword, newMasterPassword, newKdfSpec = null, enforceMinimums = true }) {
      this._assertUnlocked();
      const { updatedHeader, dek, kdfEngine } = await rewrapMasterPassword({
        header: this._header,
        currentPassword,
        newMasterPassword,
        newKdfSpec,
        enforceMinimums,
        useWorker: this._useWorker
      });
      await this.storage.atomicOperationWithSnapshot({
        reason: "master-password-change",
        newHeader: updatedHeader
      });
      this._header = updatedHeader;
      this.#dek = dek;
      this._emit("header-updated", { reason: "master-password-change" });
      return { kdfEngine };
    }
    async rotateRecoveryKeyWithPassword(masterPassword) {
      this._assertUnlocked();
      const { updatedHeader, recoveryKeyFormatted } = await rotateRecoveryKey({
        header: this._header,
        masterPassword,
        useWorker: this._useWorker
      });
      await this.storage.atomicOperationWithSnapshot({
        reason: "recovery-key-rotate",
        newHeader: updatedHeader
      });
      this._header = updatedHeader;
      return { recoveryKeyFormatted };
    }
    async setWipeAfterFailures(limit) {
      this._assertUnlocked();
      const clean = Number.isInteger(limit) && limit >= 0 && limit <= 20 ? limit : 0;
      const updatedHeader = {
        ...this._header,
        security: {
          ...this._header.security,
          wipeAfterFailures: clean
        },
        updatedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      await this.storage.saveHeader(updatedHeader);
      this._header = updatedHeader;
      return clean;
    }
    async updateSettings(partial) {
      this._settings = await this.storage.saveSettings(partial);
      if (this.isUnlocked) {
        this._scheduleInactivityLock();
      }
      this._emit("settings-updated", { settings: this._settings });
      return this._settings;
    }
    // --- Encrypted Record Access (DEK stays strictly inside #dek) ---
    async listRecords(type = null, { includeTrashed = false } = {}) {
      this._assertUnlocked();
      const envelopes = await this.storage.getAllRecords(type);
      const out = [];
      for (const env of envelopes) {
        if (!includeTrashed && env.deletedAt) continue;
        const dec = await decryptRecord(this.#dek, env, this._header.vaultId);
        out.push(dec);
      }
      return out;
    }
    async saveRecord({ id = null, type, data, deletedAt = null, createdAt = null }) {
      this._assertUnlocked();
      const recordId = id || randomId(type.slice(0, 3));
      const existing = id ? await this.storage.getRecord(id) : null;
      const env = await encryptRecord(this.#dek, {
        id: recordId,
        type,
        vaultId: this._header.vaultId,
        data,
        createdAt: createdAt || existing?.createdAt || (/* @__PURE__ */ new Date()).toISOString(),
        updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        deletedAt
      });
      await this.storage.putRecord(env);
      this.touchActivity();
      return {
        id: env.id,
        type: env.type,
        schemaVersion: env.schemaVersion,
        createdAt: env.createdAt,
        updatedAt: env.updatedAt,
        deletedAt: env.deletedAt,
        data
      };
    }
    async trashRecord(id) {
      this._assertUnlocked();
      const existing = await this.storage.getRecord(id);
      if (!existing) return;
      const dec = await decryptRecord(this.#dek, existing, this._header.vaultId);
      const env = await encryptRecord(this.#dek, {
        id: dec.id,
        type: dec.type,
        vaultId: this._header.vaultId,
        data: dec.data,
        createdAt: dec.createdAt,
        updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        deletedAt: (/* @__PURE__ */ new Date()).toISOString()
      });
      await this.storage.putRecord(env);
      this.touchActivity();
    }
    async restoreRecord(id) {
      this._assertUnlocked();
      const existing = await this.storage.getRecord(id);
      if (!existing) return;
      const dec = await decryptRecord(this.#dek, existing, this._header.vaultId);
      const env = await encryptRecord(this.#dek, {
        id: dec.id,
        type: dec.type,
        vaultId: this._header.vaultId,
        data: dec.data,
        createdAt: dec.createdAt,
        updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        deletedAt: null
      });
      await this.storage.putRecord(env);
      this.touchActivity();
    }
    async permanentlyDeleteRecord(id) {
      this._assertUnlocked();
      await this.storage.deleteRecord(id);
      this.touchActivity();
    }
    async encryptBatchForAtomicWrite(items) {
      this._assertUnlocked();
      const envelopes = [];
      for (const item of items) {
        const id = item.id || randomId(item.type.slice(0, 3));
        envelopes.push(await encryptRecord(this.#dek, {
          id,
          type: item.type,
          vaultId: this._header.vaultId,
          data: item.data,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt || (/* @__PURE__ */ new Date()).toISOString(),
          deletedAt: item.deletedAt ?? null
        }));
      }
      return envelopes;
    }
    async decryptRecord(envelope) {
      this._assertUnlocked();
      if (!envelope) return null;
      return decryptRecord(this.#dek, envelope, this._header.vaultId);
    }
    async movePasswordsToSection(ids, targetSectionId) {
      this._assertUnlocked();
      const idList = Array.from(ids || []);
      if (idList.length === 0) return 0;
      const toUpdate = [];
      for (const id of idList) {
        const env = await this.storage.getRecord(id);
        if (!env || env.type !== "password") continue;
        const dec = await decryptRecord(this.#dek, env, this._header.vaultId);
        toUpdate.push({
          id: dec.id,
          type: "password",
          createdAt: dec.createdAt,
          updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
          deletedAt: dec.deletedAt ?? null,
          data: {
            ...dec.data,
            sectionId: targetSectionId || null
          }
        });
      }
      if (toUpdate.length === 0) return 0;
      const encryptedBatch = await this.encryptBatchForAtomicWrite(toUpdate);
      await this.storage.atomicOperationWithSnapshot({
        reason: "bulk-move-section",
        putRecords: encryptedBatch
      });
      this.touchActivity();
      return toUpdate.length;
    }
    async runHealthCheck() {
      this._assertUnlocked();
      return this.storage.runVaultHealthCheck(this.#dek);
    }
    async wipeVault() {
      const nativePlugin = getNativeBiometricPlugin(this._env);
      if (nativePlugin && this._header?.vaultId) {
        try {
          await nativePlugin.deleteSecret({ key: `khazna_vault_${this._header.vaultId}` });
        } catch {
        }
      }
      clearConvenienceRamSession();
      this.lock({ broadcast: false, reason: "wiped", clearConvenience: true });
      await this.storage.wipeAll({ wipeSettings: false });
      this._header = null;
      this._emit("wiped", { reason: "manual" });
    }
    // --- Activity, Background Grace & Privacy Blur ---
    touchActivity() {
      if (!this.isUnlocked) return;
      this._lastActivityAt = this._now();
      this._scheduleInactivityLock();
    }
    _clearTimers() {
      if (this._inactivityTimer) {
        clearTimeout(this._inactivityTimer);
        this._inactivityTimer = null;
      }
      if (this._bgTimer) {
        clearTimeout(this._bgTimer);
        this._bgTimer = null;
      }
    }
    _scheduleInactivityLock() {
      if (this._inactivityTimer) {
        clearTimeout(this._inactivityTimer);
        this._inactivityTimer = null;
      }
      if (!this.isUnlocked) return;
      const sec = Math.max(30, Math.min(900, this._settings?.autoLockSec ?? 120));
      this._inactivityTimer = setTimeout(() => {
        this.lock({ reason: "inactivity" });
      }, sec * 1e3);
    }
    handleVisibilityChange(hidden) {
      if (hidden) {
        this.setPrivacyBlur(true);
        if (this.isUnlocked) {
          const graceSec = Math.max(0, Math.min(300, this._settings?.bgGraceSec ?? 15));
          if (this._bgTimer) clearTimeout(this._bgTimer);
          if (graceSec === 0) {
            this.lock({ reason: "background" });
          } else {
            this._bgTimer = setTimeout(() => {
              this.lock({ reason: "background" });
            }, graceSec * 1e3);
          }
        }
      } else {
        if (this._bgTimer) {
          clearTimeout(this._bgTimer);
          this._bgTimer = null;
        }
        this.setPrivacyBlur(false);
        if (this.isUnlocked) {
          const autoSec = Math.max(30, Math.min(900, this._settings?.autoLockSec ?? 120));
          if (this._now() - this._lastActivityAt >= autoSec * 1e3) {
            this.lock({ reason: "inactivity" });
          } else {
            this.touchActivity();
          }
        }
      }
    }
    setPrivacyBlur(blurred) {
      if (this._blurred === blurred) return;
      this._blurred = blurred;
      this._emit("privacy-blur", { blurred });
    }
    destroy() {
      this._clearTimers();
      this.clipboard.cancel();
      if (this._unsubSync) this._unsubSync();
      this.#dek = null;
    }
  };

  // src/i18n/strings.js
  var DICT = {
    ar: {
      appName: "\u062E\u0632\u0646\u0629",
      appSubtitle: "\u0645\u062F\u064A\u0631 \u0643\u0644\u0645\u0627\u062A \u0645\u0631\u0648\u0631 \u0645\u062D\u0644\u064A \u0628\u062A\u0634\u0641\u064A\u0631 \u0635\u0641\u0631\u064A \u0627\u0644\u0645\u0639\u0631\u0641\u0629",
      navPasswords: "\u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631",
      navCards: "\u0627\u0644\u0628\u0637\u0627\u0642\u0627\u062A",
      navNotes: "\u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0627\u062A",
      navStats: "\u0627\u0644\u0625\u062D\u0635\u0627\u0626\u064A\u0627\u062A",
      navSettings: "\u0627\u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A",
      lockNow: "\u0642\u0641\u0644 \u0627\u0644\u0622\u0646",
      lockedTitle: "\u0627\u0644\u062E\u0632\u0646\u0629 \u0645\u0642\u0641\u0644\u0629",
      lockedSubtitle: "\u0628\u064A\u0627\u0646\u0627\u062A\u0643 \u0645\u0634\u0641\u0651\u0631\u0629 \u0645\u062D\u0644\u064A\u0627\u064B \u0628\u0640 AES-256-GCM",
      createVaultTitle: "\u0625\u0646\u0634\u0627\u0621 \u062E\u0632\u0646\u0629 \u0645\u0634\u0641\u0651\u0631\u0629 \u062C\u062F\u064A\u062F\u0629",
      createVaultSubtitle: "\u062A\u0639\u0645\u0644 \u0661\u0660\u0660\u066A \u0639\u0644\u0649 \u062C\u0647\u0627\u0632\u0643 \u0628\u062F\u0648\u0646 \u062E\u0648\u0627\u062F\u0645 \u0623\u0648 \u062D\u0633\u0627\u0628\u0627\u062A \u0633\u062D\u0627\u0628\u064A\u0629.",
      masterPasswordLabel: "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 (\u0661\u0662 \u062D\u0631\u0641\u0627\u064B \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644)",
      confirmPasswordLabel: "\u062A\u0623\u0643\u064A\u062F \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629",
      noHintNote: "\u0644\u0627 \u064A\u062A\u0645 \u062D\u0641\u0638 \u0623\u064A \u062A\u0644\u0645\u064A\u062D \u0644\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0644\u0623\u0645\u0627\u0646\u0643. \u0625\u0630\u0627 \u0646\u0633\u064A\u062A\u0647\u0627 \u064A\u0645\u0643\u0646\u0643 \u0627\u0644\u0641\u062A\u062D \u0628\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0641\u0642\u0637.",
      createVaultBtn: "\u0625\u0646\u0634\u0627\u0621 \u0627\u0644\u062E\u0632\u0646\u0629 \u0648\u0645\u0639\u0627\u064A\u0631\u0629 \u0627\u0644\u062A\u0634\u0641\u064A\u0631",
      calibratingKdf: "\u062C\u0627\u0631\u064D \u0645\u0639\u0627\u064A\u0631\u0629 Argon2id \u0644\u062C\u0647\u0627\u0632\u0643 (~\u0661 \u062B\u0627\u0646\u064A\u0629)...",
      unlockBtn: "\u0641\u062A\u062D \u0627\u0644\u062E\u0632\u0646\u0629",
      unlocking: "\u062C\u0627\u0631\u064D \u0641\u0643 \u0627\u0644\u062A\u0634\u0641\u064A\u0631...",
      unlockWithFingerprint: "\u0627\u0644\u0641\u062A\u062D \u0628\u0627\u0644\u0628\u0635\u0645\u0629",
      useRecoveryKey: "\u0627\u0644\u0641\u062A\u062D \u0628\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F",
      backToPassword: "\u0627\u0644\u0639\u0648\u062F\u0629 \u0644\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
      recoveryModalTitle: "\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0644\u0645\u0631\u0629 \u0648\u0627\u062D\u062F\u0629 (\u0662\u0665\u0666 \u0628\u062A)",
      recoveryModalWarn: "\u064A\u064F\u0639\u0631\u0636 \u0647\u0630\u0627 \u0627\u0644\u0645\u0641\u062A\u0627\u062D \u0645\u0631\u0629 \u0648\u0627\u062D\u062F\u0629 \u0641\u0642\u0637. \u0627\u062D\u0641\u0638\u0647 \u0641\u064A \u0645\u0643\u0627\u0646 \u0622\u0645\u0646 \u062E\u0627\u0631\u062C \u0627\u0644\u062C\u0647\u0627\u0632 (\u0648\u0631\u0642\u0629 \u0623\u0648 \u062E\u0632\u0646\u0629 \u0622\u0645\u0646\u0629). \u0644\u0627 \u064A\u0645\u0643\u0646\u0646\u0627 \u0627\u0633\u062A\u0639\u0627\u062F\u062A\u0647 \u0644\u0643 \u0623\u0628\u062F\u0627\u064B.",
      copyRecoveryKey: "\u0646\u0633\u062E \u0627\u0644\u0645\u0641\u062A\u0627\u062D",
      printRecoveryKey: "\u0637\u0628\u0627\u0639\u0629",
      recoverySavedCheckbox: "\u0623\u0624\u0643\u062F \u0623\u0646\u0646\u064A \u062D\u0641\u0638\u062A \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F \u0641\u064A \u0645\u0643\u0627\u0646 \u0622\u0645\u0646",
      enterVaultBtn: "\u0627\u0644\u062F\u062E\u0648\u0644 \u0625\u0644\u0649 \u062E\u0632\u0646\u0629",
      recoveryInputLabel: "\u0645\u0641\u062A\u0627\u062D \u0627\u0644\u0627\u0633\u062A\u0631\u062F\u0627\u062F (\u0661\u0664 \u0645\u062C\u0645\u0648\u0639\u0629 \u0645\u0646 \u0664 \u0623\u062D\u0631\u0641)",
      newMasterOptional: "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0631\u0626\u064A\u0633\u064A\u0629 \u062C\u062F\u064A\u062F\u0629 (\u0627\u062E\u062A\u064A\u0627\u0631\u064A \u0644\u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u0639\u064A\u064A\u0646)",
      passwordsMismatch: "\u0643\u0644\u0645\u062A\u0627 \u0627\u0644\u0645\u0631\u0648\u0631 \u063A\u064A\u0631 \u0645\u062A\u0637\u0627\u0628\u0642\u062A\u064A\u0646.",
      searchPlaceholder: "\u0627\u0628\u062D\u062B \u0641\u064A \u0627\u0644\u062D\u0633\u0627\u0628\u0627\u062A \u0623\u0648 \u0627\u0644\u0645\u0648\u0627\u0642\u0639 \u0623\u0648 \u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0627\u062A...",
      allSections: "\u0627\u0644\u0643\u0644",
      favorites: "\u0627\u0644\u0645\u0641\u0636\u0644\u0629",
      duplicates: "\u0627\u0644\u0645\u0643\u0631\u0631\u0629",
      trash: "\u0627\u0644\u0645\u062D\u0630\u0648\u0641\u0627\u062A",
      addSection: "\u0642\u0633\u0645 \u062C\u062F\u064A\u062F",
      manageSections: "\u0627\u0644\u0623\u0642\u0633\u0627\u0645",
      sortUpdated: "\u0627\u0644\u0623\u062D\u062F\u062B \u062A\u0639\u062F\u064A\u0644\u0627\u064B",
      sortTitleAsc: "\u0627\u0644\u0627\u0633\u0645 (\u0623-\u064A)",
      sortCreated: "\u0627\u0644\u0623\u062D\u062F\u062B \u0625\u0646\u0634\u0627\u0621\u064B",
      sortFavorites: "\u0627\u0644\u0645\u0641\u0636\u0644\u0629 \u0623\u0648\u0644\u0627\u064B",
      emptyPasswords: "\u0644\u0627 \u062A\u0648\u062C\u062F \u0643\u0644\u0645\u0627\u062A \u0645\u0631\u0648\u0631 \u0647\u0646\u0627 \u0628\u0639\u062F",
      emptyPasswordsSub: "\u0627\u0636\u063A\u0637 \u0639\u0644\u0649 \u0632\u0631 (+) \u0644\u0625\u0636\u0627\u0641\u0629 \u062D\u0633\u0627\u0628 \u0623\u0648 \u0627\u0633\u062A\u0648\u0631\u062F \u0628\u064A\u0627\u0646\u0627\u062A\u0643 \u0645\u0646 \u0627\u0644\u0625\u0639\u062F\u0627\u062F\u0627\u062A.",
      copyUser: "\u0646\u0633\u062E \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645",
      copyPass: "\u0646\u0633\u062E \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
      copyCombo: "\u0646\u0633\u062E \u0645\u0632\u062F\u0648\u062C",
      copyBothNow: "\u0646\u0633\u062E \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 + \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
      moveToSection: "\u0646\u0642\u0644 \u0625\u0644\u0649 \u0642\u0633\u0645",
      sectionThemeLabel: "\u062B\u064A\u0645 \u0627\u0644\u0642\u0633\u0645",
      collapseSection: "\u0637\u064A \u0627\u0644\u0642\u0633\u0645",
      expandSection: "\u062A\u0648\u0633\u064A\u0639 \u0627\u0644\u0642\u0633\u0645",
      copiedUserAndPass: "\u062A\u0645 \u0646\u0633\u062E \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u0648\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0645\u0639\u0627\u064B",
      copyUrl: "\u0646\u0633\u062E \u0627\u0644\u0631\u0627\u0628\u0637",
      copyNotes: "\u0646\u0633\u062E \u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0627\u062A",
      copyAll: "\u0646\u0633\u062E \u0627\u0644\u0643\u0644",
      holdToReveal: "\u0627\u0636\u063A\u0637 \u0645\u0637\u0648\u0651\u0644\u0627\u064B \u0644\u0644\u0625\u0638\u0647\u0627\u0631",
      copiedToast: "\u062A\u0645 \u0627\u0644\u0646\u0633\u062E",
      clipboardWillClear: "\u0633\u064A\u064F\u0645\u0633\u062D \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0628\u0639\u062F",
      clipboardCleared: "\u062A\u0645 \u0645\u0633\u062D \u0627\u0644\u062D\u0627\u0641\u0638\u0629 (\u0623\u0641\u0636\u0644 \u062C\u0647\u062F)",
      clipboardLimitNote: "\u0645\u0644\u0627\u062D\u0638\u0629 \u0635\u0627\u062F\u0642\u0629: \u0645\u0633\u062D \u0627\u0644\u062D\u0627\u0641\u0638\u0629 \u0627\u0644\u062A\u0644\u0642\u0627\u0626\u064A \u064A\u0639\u0645\u0644 \u0641\u0642\u0637 \u0623\u062B\u0646\u0627\u0621 \u062A\u0631\u0643\u064A\u0632 \u0627\u0644\u062A\u0637\u0628\u064A\u0642 \u0648\u0644\u0627 \u064A\u0633\u062A\u0637\u064A\u0639 \u0645\u0633\u062D \u0633\u062C\u0644 \u0627\u0644\u062D\u0627\u0641\u0638\u0629 \u0641\u064A \u0646\u0638\u0627\u0645 \u0623\u0646\u062F\u0631\u0648\u064A\u062F/\u0633\u0627\u0645\u0633\u0648\u0646\u062C.",
      twoStepNextPass: "\u062A\u0645 \u0646\u0633\u062E \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 \u2014 \u0627\u0636\u063A\u0637 \u0644\u0646\u0633\u062E \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
      copyPassNow: "\u0646\u0633\u062E \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0622\u0646",
      edit: "\u062A\u0639\u062F\u064A\u0644",
      delete: "\u062D\u0630\u0641",
      restore: "\u0627\u0633\u062A\u0639\u0627\u062F\u0629",
      deleteForever: "\u062D\u0630\u0641 \u0646\u0647\u0627\u0626\u064A",
      save: "\u062D\u0641\u0638",
      cancel: "\u0625\u0644\u063A\u0627\u0621",
      close: "\u0625\u063A\u0644\u0627\u0642",
      addEntry: "\u0625\u0636\u0627\u0641\u0629 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631",
      editEntry: "\u062A\u0639\u062F\u064A\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
      titleLabel: "\u0627\u0644\u0639\u0646\u0648\u0627\u0646",
      sectionLabel: "\u0627\u0644\u0642\u0633\u0645",
      usernameLabel: "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645 / \u0627\u0644\u0628\u0631\u064A\u062F",
      passwordLabel: "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
      urlLabel: "\u0627\u0644\u0631\u0627\u0628\u0637 (URL)",
      notesLabel: "\u0645\u0644\u0627\u062D\u0638\u0627\u062A",
      generateBtn: "\u062A\u0648\u0644\u064A\u062F",
      passwordHistory: "\u0633\u062C\u0644 \u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0633\u0627\u0628\u0642\u0629 (\u0622\u062E\u0631 \u0661\u0660)",
      addCard: "\u0625\u0636\u0627\u0641\u0629 \u0628\u0637\u0627\u0642\u0629 \u0628\u0646\u0643\u064A\u0629",
      editCard: "\u062A\u0639\u062F\u064A\u0644 \u0627\u0644\u0628\u0637\u0627\u0642\u0629",
      emptyCards: "\u0644\u0627 \u062A\u0648\u062C\u062F \u0628\u0637\u0627\u0642\u0627\u062A \u0628\u0646\u0643\u064A\u0629 \u0628\u0639\u062F",
      emptyCardsSub: "\u0623\u0636\u0641 \u0628\u0637\u0627\u0642\u0627\u062A\u0643 \u0645\u0639 \u0645\u0639\u0627\u064A\u0646\u0629 \u062B\u0644\u0627\u062B\u064A\u0629 \u0627\u0644\u0623\u0628\u0639\u0627\u062F \u0648\u0625\u062E\u0641\u0627\u0621 \u062A\u0644\u0642\u0627\u0626\u064A \u0644\u0644\u0631\u0642\u0645 \u0648 CVV \u0648 PIN.",
      cardNameLabel: "\u0627\u0633\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629 (\u062A\u0633\u0645\u064A\u062A\u0643 \u0627\u0644\u062E\u0627\u0635\u0629)",
      bankNameLabel: "\u0627\u0633\u0645 \u0627\u0644\u0628\u0646\u0643",
      holderNameLabel: "\u0627\u0633\u0645 \u062D\u0627\u0645\u0644 \u0627\u0644\u0628\u0637\u0627\u0642\u0629",
      cardNumberLabel: "\u0631\u0642\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629",
      expiryLabel: "\u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621 (MM/YY)",
      cvvLabel: "\u0631\u0645\u0632 \u0627\u0644\u0623\u0645\u0627\u0646 (CVV)",
      pinLabel: "\u0627\u0644\u0631\u0642\u0645 \u0627\u0644\u0633\u0631\u064A (PIN)",
      cardBrandLabel: "\u0627\u0644\u0634\u0628\u0643\u0629 / \u0627\u0644\u0646\u0648\u0639",
      cardThemeLabel: "\u062A\u0635\u0645\u064A\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629",
      flipCard: "\u0642\u0644\u0628 \u0627\u0644\u0628\u0637\u0627\u0642\u0629",
      luhnValid: "\u0631\u0642\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629 \u0633\u0644\u064A\u0645 (Luhn \u2713)",
      luhnInvalid: "\u062A\u062D\u0630\u064A\u0631: \u0631\u0642\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629 \u0644\u0627 \u064A\u0637\u0627\u0628\u0642 \u0641\u062D\u0635 Luhn",
      partialCardBadge: "\u0628\u0637\u0627\u0642\u0629 \u062C\u0632\u0626\u064A\u0629 (\u0623\u0631\u0642\u0627\u0645 \u0648\u0633\u0637\u0649 \u063A\u064A\u0631 \u0645\u0639\u0631\u0648\u0641\u0629)",
      addNote: "\u0645\u0644\u0627\u062D\u0638\u0629 \u0645\u0634\u0641\u0651\u0631\u0629 \u062C\u062F\u064A\u062F\u0629",
      editNote: "\u062A\u0639\u062F\u064A\u0644 \u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0629",
      emptyNotes: "\u0644\u0627 \u062A\u0648\u062C\u062F \u0645\u0644\u0627\u062D\u0638\u0627\u062A \u0645\u0634\u0641\u0651\u0631\u0629 \u0628\u0639\u062F",
      emptyNotesSub: "\u0627\u062D\u0641\u0638 \u0645\u0641\u0627\u062A\u064A\u062D\u0643\u060C \u0642\u0648\u0627\u0626\u0645 \u0627\u0644\u0645\u0647\u0627\u0645\u060C \u0648\u0645\u0644\u0627\u062D\u0638\u0627\u062A\u0643 \u0627\u0644\u062D\u0633\u0627\u0633\u0629 \u0628\u062A\u0634\u0641\u064A\u0631 \u0643\u0627\u0645\u0644 \u0648\u062D\u0641\u0638 \u062A\u0644\u0642\u0627\u0626\u064A \u0644\u0644\u0645\u0633\u0648\u062F\u0627\u062A.",
      noteTitleLabel: "\u0639\u0646\u0648\u0627\u0646 \u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0629",
      noteBodyLabel: "\u0645\u062D\u062A\u0648\u0649 \u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0629",
      checklistLabel: "\u0642\u0627\u0626\u0645\u0629 \u0645\u0647\u0627\u0645 \u0627\u062E\u062A\u064A\u0627\u0631\u064A\u0629",
      addChecklistItem: "\u0625\u0636\u0627\u0641\u0629 \u0639\u0646\u0635\u0631 \u0644\u0644\u0642\u0627\u0626\u0645\u0629",
      pinNote: "\u062A\u062B\u0628\u064A\u062A \u0641\u064A \u0627\u0644\u0623\u0639\u0644\u0649",
      draftSaved: "\u062A\u0645 \u062D\u0641\u0638 \u0627\u0644\u0645\u0633\u0648\u062F\u0629 \u0645\u0634\u0641\u0651\u0631\u0629",
      statsTitle: "\u0644\u0648\u062D\u0629 \u0627\u0644\u0625\u062D\u0635\u0627\u0626\u064A\u0627\u062A \u0648\u0641\u062D\u0635 \u0627\u0644\u0623\u0645\u0627\u0646",
      totalPasswords: "\u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631",
      totalCards: "\u0627\u0644\u0628\u0637\u0627\u0642\u0627\u062A",
      totalNotes: "\u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0627\u062A",
      securityScore: "\u062F\u0631\u062C\u0629 \u0627\u0644\u0623\u0645\u0627\u0646 \u0627\u0644\u0645\u062D\u0644\u064A\u0629",
      bySectionTitle: "\u062A\u0648\u0632\u064A\u0639 \u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631 \u062D\u0633\u0628 \u0627\u0644\u0642\u0633\u0645",
      bySectionHint: "\u0627\u0636\u063A\u0637 \u0639\u0644\u0649 \u0623\u064A \u0642\u0637\u0627\u0639 \u0623\u0648 \u0642\u0633\u0645 \u0644\u0641\u062A\u062D\u0647 \u0645\u0628\u0627\u0634\u0631\u0629",
      auditWeak: "\u0643\u0644\u0645\u0627\u062A \u0645\u0631\u0648\u0631 \u0636\u0639\u064A\u0641\u0629",
      auditReused: "\u0643\u0644\u0645\u0627\u062A \u0645\u0631\u0648\u0631 \u0645\u0643\u0631\u0631\u0629",
      auditOld: "\u0642\u062F\u064A\u0645\u0629 (+\u0661\u0668\u0660 \u064A\u0648\u0645\u0627\u064B)",
      auditOfflineNote: "\u0627\u0644\u0641\u062D\u0635 \u064A\u062A\u0645 \u0645\u062D\u0644\u064A\u0627\u064B \u0661\u0660\u0660\u066A \u0628\u062F\u0648\u0646 \u0623\u064A \u0627\u062A\u0635\u0627\u0644 \u0628\u0627\u0644\u0625\u0646\u062A\u0631\u0646\u062A.",
      lastBackupLabel: "\u0622\u062E\u0631 \u0646\u0633\u062E\u0629 \u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629",
      neverBackedUp: "\u0644\u0645 \u062A\u064F\u0646\u0634\u0623 \u0646\u0633\u062E\u0629 \u0628\u0639\u062F",
      vaultSizeLabel: "\u062D\u062C\u0645 \u0627\u0644\u062E\u0632\u0646\u0629",
      backupReminderBanner: "\u0645\u0631\u0651 \u0623\u0643\u062B\u0631 \u0645\u0646 \u0667 \u0623\u064A\u0627\u0645 \u062F\u0648\u0646 \u0646\u0633\u062E\u0629 \u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 \u0645\u0634\u0641\u0651\u0631\u0629 (.vault). \u064A\u064F\u0646\u0635\u062D \u0628\u0623\u062E\u0630 \u0646\u0633\u062E\u0629 \u0627\u0644\u0622\u0646.",
      settingsSecurity: "\u0627\u0644\u0623\u0645\u0627\u0646 \u0648\u0627\u0644\u0642\u0641\u0644",
      settingsAppearance: "\u0627\u0644\u0645\u0638\u0647\u0631 \u0648\u0627\u0644\u0644\u063A\u0629",
      settingsData: "\u0627\u0644\u0646\u0633\u062E \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A \u0648\u0627\u0644\u0627\u0633\u062A\u064A\u0631\u0627\u062F",
      settingsPwa: "\u0627\u0644\u062A\u0637\u0628\u064A\u0642 \u0648\u0627\u0644\u062A\u062E\u0632\u064A\u0646 \u0648\u0627\u0644\u0646\u0632\u0627\u0647\u0629",
      langLabel: "\u0627\u0644\u0644\u063A\u0629 / Language",
      themeLabel: "\u0627\u0644\u0645\u0638\u0647\u0631",
      themeDark: "\u062F\u0627\u0643\u0646",
      themeLight: "\u0641\u0627\u062A\u062D",
      themeAmoled: "AMOLED \u0623\u0633\u0648\u062F",
      autoLockLabel: "\u0627\u0644\u0642\u0641\u0644 \u0627\u0644\u062A\u0644\u0642\u0627\u0626\u064A \u0639\u0646\u062F \u0627\u0644\u062E\u0645\u0648\u0644",
      bgGraceLabel: "\u0645\u0647\u0644\u0629 \u0627\u0644\u0642\u0641\u0644 \u0641\u064A \u0627\u0644\u062E\u0644\u0641\u064A\u0629",
      clipboardClearLabel: "\u0645\u0633\u062D \u0627\u0644\u062D\u0627\u0641\u0638\u0629 \u0627\u0644\u062A\u0644\u0642\u0627\u0626\u064A",
      copyComboModeLabel: "\u0648\u0636\u0639 \u0627\u0644\u0646\u0633\u062E \u0627\u0644\u0645\u0632\u062F\u0648\u062C",
      comboTwoStep: "\u062E\u0637\u0648\u062A\u0627\u0646 (\u0634\u0631\u064A\u0637 \u0639\u0627\u0626\u0645)",
      comboOneTap: "\u0646\u0642\u0631\u0629 \u0648\u0627\u062D\u062F\u0629 (\u0633\u0637\u0631\u0627\u0646)",
      reauthLabel: "\u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u062D\u0642\u0642 \u0644\u0644\u0625\u062C\u0631\u0627\u0621\u0627\u062A \u0627\u0644\u062D\u0633\u0627\u0633\u0629 (CVV/PIN\u060C \u0627\u0644\u062A\u0635\u062F\u064A\u0631\u060C \u0627\u0644\u0645\u0633\u062D)",
      biometricTitle: "\u0641\u062A\u062D \u0627\u0644\u062E\u0632\u0646\u0629 \u0628\u0627\u0644\u0628\u0635\u0645\u0629 (WebAuthn)",
      enableBiometric: "\u062A\u0641\u0639\u064A\u0644 \u0627\u0644\u0628\u0635\u0645\u0629",
      disableBiometric: "\u062A\u0639\u0637\u064A\u0644 \u0627\u0644\u0628\u0635\u0645\u0629",
      biometricPrfActive: "\u0645\u0641\u0639\u0651\u0644 \u0628\u0648\u0636\u0639 PRF \u0627\u0644\u062A\u0634\u0641\u064A\u0631\u064A (\u0645\u0631\u062A\u0628\u0637 \u0628\u0627\u0644\u0639\u062A\u0627\u062F)",
      biometricConvActive: "\u0645\u0641\u0639\u0651\u0644 \u0628\u0648\u0636\u0639 \u0627\u0644\u0631\u0627\u062D\u0629 (\u0630\u0627\u0643\u0631\u0629 RAM \u0641\u0642\u0637 \u2014 \u064A\u062A\u0637\u0644\u0628 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0628\u0639\u062F \u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u0634\u063A\u064A\u0644 \u0648\u0643\u0644 \u0662\u0664 \u0633\u0627\u0639\u0629)",
      biometricOff: "\u063A\u064A\u0631 \u0645\u0641\u0639\u0651\u0644",
      changeMasterPwd: "\u062A\u063A\u064A\u064A\u0631 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629",
      rotateRecoveryKey: "\u062A\u0648\u0644\u064A\u062F \u0645\u0641\u062A\u0627\u062D \u0627\u0633\u062A\u0631\u062F\u0627\u062F \u062C\u062F\u064A\u062F",
      wipeAfterLabel: "\u0645\u0633\u062D \u0627\u0644\u062E\u0632\u0646\u0629 \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0628\u0639\u062F \u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0641\u0627\u0634\u0644\u0629 (\u062E\u0637\u0631)",
      wipeAfterOff: "\u0645\u0639\u0637\u0651\u0644 (\u0645\u0648\u0635\u0649 \u0628\u0647)",
      importExportBtn: "\u0627\u0644\u0627\u0633\u062A\u064A\u0631\u0627\u062F \u0648\u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u0627\u0644\u0645\u062D\u0644\u064A",
      healthCheckBtn: "\u0641\u062D\u0635 \u0633\u0644\u0627\u0645\u0629 \u0627\u0644\u062E\u0632\u0646\u0629",
      snapshotsTitle: "\u0627\u0644\u0644\u0642\u0637\u0627\u062A \u0627\u0644\u0645\u0634\u0641\u0651\u0631\u0629 \u0627\u0644\u062A\u0644\u0642\u0627\u0626\u064A\u0629 (\u062A\u0631\u0627\u062C\u0639)",
      restoreSnapshot: "\u0627\u0633\u062A\u0639\u0627\u062F\u0629",
      installAppBtn: "\u062A\u062B\u0628\u064A\u062A \u062E\u0632\u0646\u0629 \u0639\u0644\u0649 \u0627\u0644\u0634\u0627\u0634\u0629 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629",
      installIosHint: '\u0639\u0644\u0649 Safari/iOS: \u0627\u0636\u063A\u0637 \u0632\u0631 \u0627\u0644\u0645\u0634\u0627\u0631\u0643\u0629 \u062B\u0645 "\u0625\u0636\u0627\u0641\u0629 \u0625\u0644\u0649 \u0627\u0644\u0634\u0627\u0634\u0629 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629".',
      updateAvailable: "\u064A\u062A\u0648\u0641\u0631 \u0625\u0635\u062F\u0627\u0631 \u062C\u062F\u064A\u062F \u0645\u0646 \u062E\u0632\u0646\u0629",
      updateConfirmBtn: "\u062A\u062D\u062F\u064A\u062B \u0648\u062A\u0641\u0639\u064A\u0644 \u0627\u0644\u0622\u0646",
      storageStatusLabel: "\u062D\u0627\u0644\u0629 \u0627\u0644\u062A\u062E\u0632\u064A\u0646 \u0627\u0644\u062F\u0627\u0626\u0645",
      storagePersisted: "\u0645\u062D\u0645\u064A \u0636\u062F \u0627\u0644\u062D\u0630\u0641 \u0627\u0644\u062A\u0644\u0642\u0627\u0626\u064A (Persisted \u2713)",
      storageBestEffort: "\u062A\u062E\u0632\u064A\u0646 \u0642\u064A\u0627\u0633\u064A (Best-Effort)",
      appVersionLabel: "\u0625\u0635\u062F\u0627\u0631 \u0627\u0644\u062A\u0637\u0628\u064A\u0642",
      appShellHashLabel: "\u0628\u0635\u0645\u0629 SHA-256 \u0644\u0647\u064A\u0643\u0644 \u0627\u0644\u062A\u0637\u0628\u064A\u0642",
      screenshotHonesty: "\u0645\u0644\u0627\u062D\u0638\u0629 \u0623\u0645\u0646\u064A\u0629 \u0635\u0627\u062F\u0642\u0629: \u062A\u0637\u0628\u064A\u0642\u0627\u062A \u0627\u0644\u0648\u064A\u0628 (PWA) \u0644\u0627 \u062A\u0633\u062A\u0637\u064A\u0639 \u0645\u0646\u0639 \u0644\u0642\u0637\u0627\u062A \u0627\u0644\u0634\u0627\u0634\u0629 \u0639\u0644\u0649 \u0623\u0646\u062F\u0631\u0648\u064A\u062F (FLAG_SECURE \u063A\u064A\u0631 \u0645\u062A\u0627\u062D \u0644\u0644\u0645\u062A\u0635\u0641\u062D). \u062A\u0645 \u062A\u0641\u0639\u064A\u0644 \u062A\u0645\u0648\u064A\u0647 \u0627\u0644\u062E\u0635\u0648\u0635\u064A\u0629 \u0639\u0646\u062F \u0641\u0642\u062F\u0627\u0646 \u0627\u0644\u062A\u0631\u0643\u064A\u0632 \u0643\u0623\u0641\u0636\u0644 \u062C\u0647\u062F.",
      wipeVaultBtn: "\u062D\u0630\u0641 \u0627\u0644\u062E\u0632\u0646\u0629 \u0628\u0627\u0644\u0643\u0627\u0645\u0644",
      wipeVaultWarn: "\u062A\u062D\u0630\u064A\u0631 \u0623\u062D\u0645\u0631: \u0633\u064A\u062A\u0645 \u062D\u0630\u0641 \u062C\u0645\u064A\u0639 \u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631 \u0648\u0627\u0644\u0628\u0637\u0627\u0642\u0627\u062A \u0648\u0627\u0644\u0645\u0644\u0627\u062D\u0638\u0627\u062A \u0648\u0627\u0644\u0644\u0642\u0637\u0627\u062A \u0646\u0647\u0627\u0626\u064A\u0627\u064B \u0645\u0646 \u0647\u0630\u0627 \u0627\u0644\u062C\u0647\u0627\u0632 \u0648\u0644\u0627 \u064A\u0645\u0643\u0646 \u0627\u0644\u062A\u0631\u0627\u062C\u0639 \u0625\u0644\u0627 \u0645\u0646 \u0646\u0633\u062E\u0629 \u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 \u062E\u0627\u0631\u062C\u064A\u0629.",
      reauthTitle: "\u062A\u0623\u0643\u064A\u062F \u0627\u0644\u0647\u0648\u064A\u0629 \u0645\u0637\u0644\u0648\u0628",
      reauthSubtitle: "\u0647\u0630\u0627 \u0627\u0644\u0625\u062C\u0631\u0627\u0621 \u062D\u0633\u0627\u0633. \u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0623\u0648 \u0627\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u0628\u0635\u0645\u0629 \u0644\u0644\u0645\u062A\u0627\u0628\u0639\u0629.",
      confirmBtn: "\u062A\u0623\u0643\u064A\u062F",
      generatorTitle: "\u0645\u0648\u0644\u0651\u062F \u0643\u0644\u0645\u0627\u062A \u0627\u0644\u0645\u0631\u0648\u0631 (CSPRNG)",
      genModePassword: "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631",
      genModePassphrase: "\u0639\u0628\u0627\u0631\u0629 \u0645\u0631\u0648\u0631",
      genLength: "\u0627\u0644\u0637\u0648\u0644",
      genWords: "\u0639\u062F\u062F \u0627\u0644\u0643\u0644\u0645\u0627\u062A",
      genLower: "\u0623\u062D\u0631\u0641 \u0635\u063A\u064A\u0631\u0629 (a-z)",
      genUpper: "\u0623\u062D\u0631\u0641 \u0643\u0628\u064A\u0631\u0629 (A-Z)",
      genDigits: "\u0623\u0631\u0642\u0627\u0645 (0-9)",
      genSymbols: "\u0631\u0645\u0648\u0632 (!@#)",
      genNoLookalikes: "\u0627\u0633\u062A\u0628\u0639\u0627\u062F \u0627\u0644\u0623\u062D\u0631\u0641 \u0627\u0644\u0645\u062A\u0634\u0627\u0628\u0647\u0629 (0/O, 1/I/l)",
      genUse: "\u0627\u0633\u062A\u062E\u062F\u0627\u0645",
      importTitle: "\u0627\u0644\u0627\u0633\u062A\u064A\u0631\u0627\u062F \u0648\u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u0627\u0644\u0645\u062D\u0644\u064A \u0661\u0660\u0660\u066A",
      tabImport: "\u0627\u0633\u062A\u064A\u0631\u0627\u062F",
      tabExport: "\u062A\u0635\u062F\u064A\u0631",
      pickFileBtn: "\u0627\u062E\u062A\u064A\u0627\u0631 \u0645\u0644\u0641 (.vault, .spass, JSON, CSV)",
      pasteTextLabel: "\u0623\u0648 \u0627\u0644\u0635\u0642 \u0627\u0644\u0645\u062D\u062A\u0648\u0649 \u0645\u0628\u0627\u0634\u0631\u0629 \u0647\u0646\u0627",
      importPwdLabel: "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0644\u0641 (\u0644\u0640 .vault \u0623\u0648 .spass \u0641\u0642\u0637)",
      analyzeImportBtn: "\u062A\u062D\u0644\u064A\u0644 \u0648\u0645\u0639\u0627\u064A\u0646\u0629 \u0642\u0628\u0644 \u0627\u0644\u0627\u0633\u062A\u064A\u0631\u0627\u062F",
      commitImportBtn: "\u062A\u0646\u0641\u064A\u0630 \u0627\u0644\u0627\u0633\u062A\u064A\u0631\u0627\u062F (\u0645\u0639 \u0644\u0642\u0637\u0629 \u062A\u0631\u0627\u062C\u0639 \u062A\u0644\u0642\u0627\u0626\u064A\u0629)",
      undoImportBtn: "\u062A\u0631\u0627\u062C\u0639 \u0639\u0646 \u0622\u062E\u0631 \u0627\u0633\u062A\u064A\u0631\u0627\u062F",
      deletePlaintextReminder: "\u062A\u0630\u0643\u064A\u0631 \u0623\u0645\u0646\u064A: \u0627\u062D\u0630\u0641 \u0645\u0644\u0641 \u0627\u0644\u0646\u0635 \u063A\u064A\u0631 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 \u0645\u0646 \u062C\u0647\u0627\u0632\u0643 \u0648\u0633\u0644\u0629 \u0627\u0644\u0645\u0647\u0645\u0644\u0627\u062A \u0641\u0648\u0631 \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621.",
      spassHonestNote: "\u0645\u0644\u0627\u062D\u0638\u0629: \u0635\u064A\u063A\u0629 Samsung Pass (.spass) \u063A\u064A\u0631 \u0631\u0633\u0645\u064A\u0629 \u0648\u0642\u062F \u062A\u062E\u062A\u0644\u0641 \u0628\u064A\u0646 \u0627\u0644\u0625\u0635\u062F\u0627\u0631\u0627\u062A \u2014 \u0627\u062E\u062A\u0628\u0631\u0647\u0627 \u0628\u0645\u0644\u0641\u0643 \u0627\u0644\u062D\u0642\u064A\u0642\u064A \u0648\u062A\u0623\u0643\u0651\u062F \u0645\u0646 \u0627\u0644\u0645\u0639\u0627\u064A\u0646\u0629.",
      plainExportWarn: "\u062A\u062D\u0630\u064A\u0631 \u0623\u062D\u0645\u0631: \u0647\u0630\u0627 \u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u063A\u064A\u0631 \u0645\u0634\u0641\u0651\u0631! \u0623\u064A \u0634\u062E\u0635 \u064A\u062D\u0635\u0644 \u0639\u0644\u0649 \u0627\u0644\u0645\u0644\u0641 \u0633\u064A\u062A\u0645\u0643\u0646 \u0645\u0646 \u0642\u0631\u0627\u0621\u0629 \u062C\u0645\u064A\u0639 \u0643\u0644\u0645\u0627\u062A \u0645\u0631\u0648\u0631\u0643.",
      offlineBadge: "\u0648\u0636\u0639 \u0639\u062F\u0645 \u0627\u0644\u0627\u062A\u0635\u0627\u0644 \u2014 \u0643\u0644 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u062A\u0639\u0645\u0644 \u0645\u062D\u0644\u064A\u0627\u064B",
      privacyOverlayTitle: "\u062E\u0632\u0646\u0629 \u0645\u062D\u0645\u064A\u0629",
      privacyOverlaySub: "\u062A\u0645 \u0625\u062E\u0641\u0627\u0621 \u0627\u0644\u0645\u062D\u062A\u0648\u0649 \u0644\u062D\u0645\u0627\u064A\u0629 \u062E\u0635\u0648\u0635\u064A\u062A\u0643",
      secDeleteTitle: "\u062D\u0630\u0641 \u0627\u0644\u0642\u0633\u0645",
      secDeleteMove: "\u0646\u0642\u0644 \u0627\u0644\u0639\u0646\u0627\u0635\u0631 \u0625\u0644\u0649 \u0642\u0633\u0645 \u0622\u062E\u0631 \u062B\u0645 \u062D\u0630\u0641 \u0627\u0644\u0642\u0633\u0645",
      secDeleteTrash: "\u0646\u0642\u0644 \u0639\u0646\u0627\u0635\u0631 \u0627\u0644\u0642\u0633\u0645 \u0625\u0644\u0649 \u0627\u0644\u0645\u062D\u0630\u0648\u0641\u0627\u062A (\u0663\u0660 \u064A\u0648\u0645\u0627\u064B)",
      multiSelectCount: "\u0645\u062D\u062F\u062F",
      moveToTrash: "\u0646\u0642\u0644 \u0644\u0644\u0645\u062D\u0630\u0648\u0641\u0627\u062A",
      cancelSelection: "\u0625\u0644\u063A\u0627\u0621 \u0627\u0644\u062A\u062D\u062F\u064A\u062F",
      seconds: "\u062B\u0627\u0646\u064A\u0629",
      minutes: "\u062F\u0642\u064A\u0642\u0629",
      syncBtnShort: "\u0645\u0632\u0627\u0645\u0646\u0629",
      syncTitle: "\u0645\u0632\u0627\u0645\u0646\u0629 \u0628\u064A\u0646 \u0627\u0644\u0623\u062C\u0647\u0632\u0629 (\u0645\u0634\u0641\u0651\u0631\u0629 \u0661\u0660\u0660\u066A)",
      syncTabSend: "\u0625\u0631\u0633\u0627\u0644 \u0644\u062C\u0647\u0627\u0632 \u0622\u062E\u0631",
      syncTabReceive: "\u0627\u0633\u062A\u0642\u0628\u0627\u0644 \u0648\u0645\u0632\u0627\u0645\u0646\u0629",
      syncSecurityNote: "\u0627\u0644\u0631\u0627\u0628\u0637 \u064A\u062D\u062A\u0648\u064A \u0641\u0642\u0637 \u0639\u0644\u0649 \u0628\u064A\u0627\u0646\u0627\u062A \u0645\u0634\u0641\u0651\u0631\u0629 (AES-256-GCM) \u062F\u0627\u062E\u0644 \u062C\u0632\u0621 \u0627\u0644\u0631\u0627\u0628\u0637 (#sync) \u0627\u0644\u0630\u064A \u0644\u0627 \u064A\u064F\u0631\u0633\u0644 \u0623\u0628\u062F\u0627\u064B \u0644\u0623\u064A \u062E\u0627\u062F\u0645\u060C \u0648\u0644\u0627 \u064A\u062A\u0636\u0645\u0646 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631. \u0639\u0646\u062F \u0641\u062A\u062D\u0647 \u0639\u0644\u0649 \u0627\u0644\u0647\u0627\u062A\u0641 \u0633\u064A\u064F\u0643\u062A\u0628 \u0627\u0644\u0643\u0648\u062F \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0641\u064A \u0645\u0643\u0627\u0646\u0647.",
      syncScopeLabel: "\u0646\u0637\u0627\u0642 \u0627\u0644\u062A\u062D\u062F\u064A\u062B",
      syncScopeDelta: "\u0623\u062D\u062F\u062B \u0627\u0644\u062A\u0639\u062F\u064A\u0644\u0627\u062A \u0641\u0642\u0637 (\u0645\u0636\u063A\u0648\u0637 \u0644\u0644\u0631\u0627\u0628\u0637)",
      syncScopeFull: "\u0643\u0644 \u0627\u0644\u062E\u0632\u0646\u0629 (\u0646\u0633\u062E\u0629 \u0643\u0627\u0645\u0644\u0629)",
      syncPassLabel: "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 (\u064A\u064F\u0643\u062A\u0628\u0647\u0627 \u0627\u0644\u062C\u0647\u0627\u0632 \u0627\u0644\u0622\u062E\u0631)",
      syncPassPlaceholder: "\u0627\u062E\u062A\u0631 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0645\u0624\u0642\u062A\u0629 \u0623\u0648 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u062E\u0632\u0646\u062A\u0643",
      syncGenPassBtn: "\u062A\u0648\u0644\u064A\u062F",
      syncGenerateBtn: "\u0625\u0646\u0634\u0627\u0621 \u0631\u0627\u0628\u0637 \u0648\u0643\u0648\u062F \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u0645\u0634\u0641\u0651\u0631",
      syncNothingToSend: "\u0644\u0627 \u062A\u0648\u062C\u062F \u062A\u0639\u062F\u064A\u0644\u0627\u062A \u062C\u062F\u064A\u062F\u0629 \u0645\u0646\u0630 \u0622\u062E\u0631 \u0645\u0632\u0627\u0645\u0646\u0629. \u0627\u062E\u062A\u0631 \xAB\u0643\u0644 \u0627\u0644\u062E\u0632\u0646\u0629\xBB \u0644\u0625\u0631\u0633\u0627\u0644 \u0646\u0633\u062E\u0629 \u0643\u0627\u0645\u0644\u0629.",
      syncReadySummary: "\u062C\u0627\u0647\u0632 \u0644\u0644\u0625\u0631\u0633\u0627\u0644 \u0627\u0644\u0645\u0634\u0641\u0651\u0631",
      syncOneTapLinkLabel: "\u0631\u0627\u0628\u0637 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0628\u0636\u063A\u0637\u0629 \u0648\u0627\u062D\u062F\u0629 (\u064A\u0641\u062A\u062D \u0627\u0644\u062A\u0637\u0628\u064A\u0642 \u0648\u064A\u0643\u062A\u0628 \u0627\u0644\u0643\u0648\u062F \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B)",
      syncCopyLinkBtn: "\u0646\u0633\u062E \u0627\u0644\u0631\u0627\u0628\u0637",
      syncShareLinkBtn: "\u0645\u0634\u0627\u0631\u0643\u0629 \u0627\u0644\u0631\u0627\u0628\u0637",
      syncShareText: "\u0631\u0627\u0628\u0637 \u0645\u0632\u0627\u0645\u0646\u0629 \u062E\u0632\u0646\u0629 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 (\u064A\u062D\u062A\u0627\u062C \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629)",
      syncLinkCopied: "\u062A\u0645 \u0646\u0633\u062E \u0631\u0627\u0628\u0637 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 \u2713",
      syncCodeLabel: "\u0623\u0648 \u0627\u0646\u0633\u062E \u0643\u0648\u062F \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u0646\u0635\u064A",
      syncCopyCodeBtn: "\u0646\u0633\u062E \u0627\u0644\u0643\u0648\u062F",
      syncCodeCopied: "\u062A\u0645 \u0646\u0633\u062E \u0643\u0648\u062F \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u2713",
      syncCopyManual: "\u0627\u0646\u0633\u062E \u0627\u0644\u0646\u0635 \u0627\u0644\u0645\u062D\u062F\u062F \u064A\u062F\u0648\u064A\u0627\u064B",
      syncTooLargeForLink: "\u062D\u062C\u0645 \u0627\u0644\u062E\u0632\u0646\u0629 \u0627\u0644\u0643\u0627\u0645\u0644\u0629 \u0643\u0628\u064A\u0631 \u0639\u0644\u0649 \u0631\u0627\u0628\u0637 \u0648\u0627\u062A\u0633\u0627\u0628/\u0627\u0644\u0645\u062A\u0635\u0641\u062D \u2014 \u0627\u0633\u062A\u062E\u062F\u0645 \xAB\u0623\u062D\u062F\u062B \u0627\u0644\u062A\u0639\u062F\u064A\u0644\u0627\u062A \u0641\u0642\u0637\xBB \u0623\u0648 \u0627\u0646\u0633\u062E \u0627\u0644\u0643\u0648\u062F \u0628\u0627\u0644\u0623\u0633\u0641\u0644 \u0623\u0648 \u0635\u062F\u0651\u0631 \u0645\u0644\u0641 .vault.",
      syncAutofilledBanner: "\u062A\u0645 \u0627\u0633\u062A\u0644\u0627\u0645 \u0643\u0648\u062F \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B \u0645\u0646 \u0627\u0644\u0631\u0627\u0628\u0637! \u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0648\u0627\u0636\u063A\u0637 \u0645\u0639\u0627\u064A\u0646\u0629.",
      syncPendingUnlockBanner: "\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 \u0631\u0627\u0628\u0637 \u0645\u0632\u0627\u0645\u0646\u0629 \u0645\u0634\u0641\u0651\u0631 \u2014 \u0627\u0641\u062A\u062D \u062E\u0632\u0646\u062A\u0643 \u0627\u0644\u0622\u0646 \u0644\u064A\u062A\u0645 \u062A\u0639\u0628\u0626\u0629 \u0627\u0644\u0643\u0648\u062F \u0648\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u062A\u062D\u062F\u064A\u062B \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B.",
      syncReceiveCodeLabel: "\u0643\u0648\u062F \u0623\u0648 \u0631\u0627\u0628\u0637 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u0645\u0634\u0641\u0651\u0631",
      syncReceivePlaceholder: "\u0627\u0644\u0635\u0642 KHAZNA-SYNC-1:... \u0623\u0648 \u0627\u0644\u0631\u0627\u0628\u0637 \u0627\u0644\u0643\u0627\u0645\u0644 \u0647\u0646\u0627",
      syncStrategyLabel: "\u0637\u0631\u064A\u0642\u0629 \u0627\u0644\u062F\u0645\u062C \u0627\u0644\u0622\u0645\u0646",
      syncStrategySmart: "\u062F\u0645\u062C \u0630\u0643\u064A (\u0627\u0644\u0623\u062D\u062F\u062B \u062A\u0627\u0631\u064A\u062E\u0627\u064B \u064A\u0641\u0648\u0632 \u0648\u0644\u0627 \u064A\u064F\u062D\u0630\u0641 \u0623\u064A \u0639\u0646\u0635\u0631)",
      syncStrategyAddOnly: "\u0625\u0636\u0627\u0641\u0629 \u0627\u0644\u0639\u0646\u0627\u0635\u0631 \u0627\u0644\u062C\u062F\u064A\u062F\u0629 \u0641\u0642\u0637 \u062F\u0648\u0646 \u062A\u0639\u062F\u064A\u0644 \u0627\u0644\u062D\u0627\u0644\u064A",
      syncPreviewBtn: "\u0641\u0643 \u0627\u0644\u062A\u0634\u0641\u064A\u0631 \u0648\u0645\u0639\u0627\u064A\u0646\u0629 \u0627\u0644\u0641\u0631\u0648\u0642\u0627\u062A",
      syncPreviewDiff: "\u0645\u0639\u0627\u064A\u0646\u0629 \u0627\u0644\u062F\u0645\u062C",
      syncAddedLabel: "\u062C\u062F\u064A\u062F",
      syncUpdatedLabel: "\u0645\u062D\u062F\u0651\u062B",
      syncUnchangedLabel: "\u0645\u062A\u0637\u0627\u0628\u0642",
      syncApplyBtn: "\u062A\u0623\u0643\u064A\u062F \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u0622\u0646 (\u0645\u0639 \u0644\u0642\u0637\u0629 \u062A\u0631\u0627\u062C\u0639 \u062A\u0644\u0642\u0627\u0626\u064A\u0629)",
      syncSuccessToast: "\u062A\u0645\u062A \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0628\u0646\u062C\u0627\u062D",
      syncSettingsBtn: "\u0645\u0632\u0627\u0645\u0646\u0629 \u0628\u064A\u0646 \u0627\u0644\u0623\u062C\u0647\u0632\u0629 (\u0631\u0627\u0628\u0637 / \u0643\u0648\u062F)",
      downloadZipBtn: "\u062A\u0646\u0632\u064A\u0644 \u0645\u0644\u0641\u0627\u062A \u0627\u0644\u062A\u0637\u0628\u064A\u0642 (khazna-pwa.zip)",
      downloadZipShort: "ZIP",
      downloadZipToast: "\u0628\u062F\u0623 \u062A\u0646\u0632\u064A\u0644 \u0645\u0644\u0641 khazna-pwa.zip \u2713"
    },
    en: {
      appName: "Khazna",
      appSubtitle: "Local-only zero-knowledge password manager",
      navPasswords: "Passwords",
      navCards: "Cards",
      navNotes: "Notes",
      navStats: "Stats",
      navSettings: "Settings",
      lockNow: "Lock Now",
      lockedTitle: "Vault Locked",
      lockedSubtitle: "Encrypted locally with AES-256-GCM",
      createVaultTitle: "Create Encrypted Vault",
      createVaultSubtitle: "100% on-device. Zero servers, zero accounts, zero tracking.",
      masterPasswordLabel: "Master Password (min 12 characters)",
      confirmPasswordLabel: "Confirm Master Password",
      noHintNote: "No password hint is stored. If forgotten, only your Recovery Key can unlock the vault.",
      createVaultBtn: "Create Vault & Calibrate KDF",
      calibratingKdf: "Calibrating Argon2id for your device (~1s)...",
      unlockBtn: "Unlock Vault",
      unlocking: "Decrypting...",
      unlockWithFingerprint: "Unlock with Biometrics",
      useRecoveryKey: "Unlock with Recovery Key",
      backToPassword: "Back to Master Password",
      recoveryModalTitle: "One-Time Recovery Key (256-bit)",
      recoveryModalWarn: "Shown ONCE only. Store it safely offline (paper or safe). It cannot be recovered later.",
      copyRecoveryKey: "Copy Key",
      printRecoveryKey: "Print",
      recoverySavedCheckbox: "I confirm I have saved this Recovery Key safely",
      enterVaultBtn: "Enter Khazna",
      recoveryInputLabel: "Recovery Key (14 groups of 4 chars)",
      newMasterOptional: "New Master Password (optional reset)",
      passwordsMismatch: "Passwords do not match.",
      searchPlaceholder: "Search accounts, URLs, or notes...",
      allSections: "All",
      favorites: "Favorites",
      duplicates: "Duplicates",
      trash: "Trash",
      addSection: "New Section",
      manageSections: "Sections",
      sortUpdated: "Recently Updated",
      sortTitleAsc: "Title (A\u2013Z)",
      sortCreated: "Newest Created",
      sortFavorites: "Favorites First",
      emptyPasswords: "No passwords here yet",
      emptyPasswordsSub: "Tap (+) to add an entry or import locally from Settings.",
      copyUser: "Copy User",
      copyPass: "Copy Password",
      copyCombo: "Copy Combo",
      copyBothNow: "Copy User + Password",
      moveToSection: "Move to Section",
      sectionThemeLabel: "Section Theme",
      collapseSection: "Collapse Section",
      expandSection: "Expand Section",
      copiedUserAndPass: "Username & password copied together",
      copyUrl: "Copy URL",
      copyNotes: "Copy Notes",
      copyAll: "Copy All",
      holdToReveal: "Press & hold to reveal",
      copiedToast: "Copied",
      clipboardWillClear: "Auto-clears in",
      clipboardCleared: "Clipboard cleared (best effort)",
      clipboardLimitNote: "Honest note: Clipboard auto-clear only works while the app has focus and cannot wipe Android/Samsung/Gboard clipboard history.",
      twoStepNextPass: "Username copied \u2014 tap to copy password",
      copyPassNow: "Copy Password Now",
      edit: "Edit",
      delete: "Delete",
      restore: "Restore",
      deleteForever: "Delete Forever",
      save: "Save",
      cancel: "Cancel",
      close: "Close",
      addEntry: "Add Password",
      editEntry: "Edit Password",
      titleLabel: "Title",
      sectionLabel: "Section",
      usernameLabel: "Username / Email",
      passwordLabel: "Password",
      urlLabel: "URL",
      notesLabel: "Notes",
      generateBtn: "Generate",
      passwordHistory: "Password History (last 10)",
      addCard: "Add Bank Card",
      editCard: "Edit Bank Card",
      emptyCards: "No bank cards yet",
      emptyCardsSub: "Add cards with live 3D preview and masked Number, CVV & PIN.",
      cardNameLabel: "Card Name (your label)",
      bankNameLabel: "Bank Name",
      holderNameLabel: "Cardholder Name",
      cardNumberLabel: "Card Number",
      expiryLabel: "Expiry (MM/YY)",
      cvvLabel: "Security Code (CVV)",
      pinLabel: "Card PIN",
      cardBrandLabel: "Card Network",
      cardThemeLabel: "Card Theme",
      flipCard: "Flip Card",
      luhnValid: "Card number valid (Luhn \u2713)",
      luhnInvalid: "Warning: Card number fails Luhn check",
      partialCardBadge: "Partial card (unknown middle digits)",
      addNote: "New Secure Note",
      editNote: "Edit Secure Note",
      emptyNotes: "No secure notes yet",
      emptyNotesSub: "Store sensitive notes and checklists with encrypted autosave drafts.",
      noteTitleLabel: "Note Title",
      noteBodyLabel: "Note Body",
      checklistLabel: "Optional Checklist",
      addChecklistItem: "Add checklist item",
      pinNote: "Pin to top",
      draftSaved: "Encrypted draft saved",
      statsTitle: "Statistics & Security Audit",
      totalPasswords: "Passwords",
      totalCards: "Cards",
      totalNotes: "Notes",
      securityScore: "Local Security Score",
      bySectionTitle: "Passwords by Section",
      bySectionHint: "Tap a slice or row to open that section",
      auditWeak: "Weak Passwords",
      auditReused: "Reused Passwords",
      auditOld: "Old (> 180 days)",
      auditOfflineNote: "100% offline audit \u2014 zero network breach checks.",
      lastBackupLabel: "Last Backup",
      neverBackedUp: "Never backed up",
      vaultSizeLabel: "Vault Size",
      backupReminderBanner: "Over 7 days since your last encrypted (.vault) backup. Consider backing up now.",
      settingsSecurity: "Security & Lock",
      settingsAppearance: "Appearance & Language",
      settingsData: "Backup, Import & Export",
      settingsPwa: "PWA, Storage & Integrity",
      langLabel: "Language / \u0627\u0644\u0644\u063A\u0629",
      themeLabel: "Theme",
      themeDark: "Dark",
      themeLight: "Light",
      themeAmoled: "AMOLED Black",
      autoLockLabel: "Inactivity Auto-Lock",
      bgGraceLabel: "Background Grace Period",
      clipboardClearLabel: "Clipboard Auto-Clear",
      copyComboModeLabel: "Copy Combo Mode",
      comboTwoStep: "Two-step (floating bar)",
      comboOneTap: "One tap (two lines)",
      reauthLabel: "Re-authenticate for sensitive actions (CVV/PIN, export, wipe)",
      biometricTitle: "Biometric Unlock (WebAuthn)",
      enableBiometric: "Enable Biometrics",
      disableBiometric: "Disable Biometrics",
      biometricPrfActive: "Enabled via WebAuthn PRF (hardware-bound)",
      biometricConvActive: "Enabled via Convenience Mode (RAM-only \u2014 Master Password required after cold start & every 24h)",
      biometricOff: "Disabled",
      changeMasterPwd: "Change Master Password",
      rotateRecoveryKey: "Rotate Recovery Key",
      wipeAfterLabel: "Auto-wipe after failed attempts (Danger)",
      wipeAfterOff: "Disabled (Recommended)",
      importExportBtn: "Local Import / Export",
      healthCheckBtn: "Run Vault Health Check",
      snapshotsTitle: "Rolling Encrypted Snapshots (Undo)",
      restoreSnapshot: "Restore",
      installAppBtn: "Install Khazna on Home Screen",
      installIosHint: 'On iOS Safari: tap Share then "Add to Home Screen".',
      updateAvailable: "A new version of Khazna is ready",
      updateConfirmBtn: "Activate Update Now",
      storageStatusLabel: "Persistent Storage",
      storagePersisted: "Protected from eviction (Persisted \u2713)",
      storageBestEffort: "Best-Effort Storage",
      appVersionLabel: "App Version",
      appShellHashLabel: "App Shell SHA-256",
      screenshotHonesty: "Honest security note: PWAs cannot block Android screenshots (FLAG_SECURE is unavailable to browsers). Privacy blur on focus loss is enabled as best effort.",
      wipeVaultBtn: "Wipe Entire Vault",
      wipeVaultWarn: "RED WARNING: Permanently deletes all passwords, cards, notes, and snapshots on this device. Irreversible without an external backup.",
      reauthTitle: "Re-authentication Required",
      reauthSubtitle: "This action is sensitive. Confirm with your Master Password or Biometrics.",
      confirmBtn: "Confirm",
      generatorTitle: "Password Generator (CSPRNG)",
      genModePassword: "Password",
      genModePassphrase: "Passphrase",
      genLength: "Length",
      genWords: "Word Count",
      genLower: "Lowercase (a-z)",
      genUpper: "Uppercase (A-Z)",
      genDigits: "Digits (0-9)",
      genSymbols: "Symbols (!@#)",
      genNoLookalikes: "Exclude look-alikes (0/O, 1/I/l)",
      genUse: "Use Password",
      importTitle: "100% Local Import & Export",
      tabImport: "Import",
      tabExport: "Export",
      pickFileBtn: "Choose File (.vault, .spass, JSON, CSV)",
      pasteTextLabel: "Or paste text directly here",
      importPwdLabel: "File Password (.vault or .spass only)",
      analyzeImportBtn: "Analyze & Preview Import",
      commitImportBtn: "Commit Import (with Auto Snapshot)",
      undoImportBtn: "Undo Last Import",
      deletePlaintextReminder: "Security reminder: Delete any plaintext export file from your device and trash immediately.",
      spassHonestNote: "Note: Samsung Pass (.spass) is proprietary and unofficial \u2014 test with your real export and review the preview.",
      plainExportWarn: "RED WARNING: Plaintext export is UNENCRYPTED. Anyone with this file can read all your secrets.",
      offlineBadge: "Offline Mode \u2014 Everything runs locally",
      privacyOverlayTitle: "Khazna Protected",
      privacyOverlaySub: "Content hidden while app is inactive",
      secDeleteTitle: "Delete Section",
      secDeleteMove: "Move items to another section, then delete",
      secDeleteTrash: "Move section items to Trash (30-day restore)",
      multiSelectCount: "selected",
      moveToTrash: "Move to Trash",
      cancelSelection: "Cancel",
      seconds: "sec",
      minutes: "min",
      syncBtnShort: "Sync",
      syncTitle: "Device-to-Device Sync (100% Encrypted)",
      syncTabSend: "Send to Device",
      syncTabReceive: "Receive & Merge",
      syncSecurityNote: "The link puts ONLY AES-256-GCM ciphertext inside the URL fragment (#sync), which is never sent to any server, and never includes your passphrase. Opening it on another device auto-fills the code.",
      syncScopeLabel: "Sync Scope",
      syncScopeDelta: "Latest Changes Only (compact for link)",
      syncScopeFull: "Entire Vault (full sync)",
      syncPassLabel: "Sync Passphrase (entered on target device)",
      syncPassPlaceholder: "Enter a temporary passphrase or your vault password",
      syncGenPassBtn: "Generate",
      syncGenerateBtn: "Generate Encrypted Sync Link & Code",
      syncNothingToSend: 'No new changes since last sync. Switch to "Entire Vault" to send everything.',
      syncReadySummary: "Encrypted package ready",
      syncOneTapLinkLabel: "One-Tap Sync Link (opens app & auto-fills code)",
      syncCopyLinkBtn: "Copy Link",
      syncShareLinkBtn: "Share Link",
      syncShareText: "Encrypted Khazna sync link (requires sync passphrase)",
      syncLinkCopied: "Encrypted sync link copied \u2713",
      syncCodeLabel: "Or copy raw sync code",
      syncCopyCodeBtn: "Copy Code",
      syncCodeCopied: "Sync code copied \u2713",
      syncCopyManual: "Copy the selected text manually",
      syncTooLargeForLink: 'Full vault is too large for a URL \u2014 use "Latest Changes Only", copy the code below, or export a .vault file.',
      syncAutofilledBanner: "Sync code auto-filled from link! Enter the sync passphrase and tap Preview.",
      syncPendingUnlockBanner: "Encrypted sync link detected \u2014 unlock your vault to auto-fill and merge updates.",
      syncReceiveCodeLabel: "Encrypted Sync Code or Link",
      syncReceivePlaceholder: "Paste KHAZNA-SYNC-1:... or full sync link here",
      syncStrategyLabel: "Safe Merge Mode",
      syncStrategySmart: "Smart Merge (newest wins, nothing deleted)",
      syncStrategyAddOnly: "Add Missing Only (never overwrite existing)",
      syncPreviewBtn: "Decrypt & Preview Diff",
      syncPreviewDiff: "Merge Preview",
      syncAddedLabel: "new",
      syncUpdatedLabel: "updated",
      syncUnchangedLabel: "unchanged",
      syncApplyBtn: "Apply Sync Now (with Auto Snapshot)",
      syncSuccessToast: "Sync completed",
      syncSettingsBtn: "Device Sync (Link / Code)",
      downloadZipBtn: "Download App Files (khazna-pwa.zip)",
      downloadZipShort: "ZIP",
      downloadZipToast: "Downloading khazna-pwa.zip \u2713"
    }
  };
  function t(lang, key) {
    const table = DICT[lang === "en" ? "en" : "ar"];
    return table[key] ?? DICT.ar[key] ?? key;
  }
  function formatError(err, lang = "ar") {
    if (err && typeof err === "object") {
      if (lang === "en" && err.en) return err.en;
      if (err.ar) return err.ar;
      if (err.message) return err.message;
    }
    return lang === "en" ? "Unexpected error occurred." : "\u062D\u062F\u062B \u062E\u0637\u0623 \u063A\u064A\u0631 \u0645\u062A\u0648\u0642\u0639.";
  }

  // src/import-export/sync.js
  var SYNC_PREFIX = "KHAZNA-SYNC-1:";
  var SYNC_HASH_KEY = "sync=";
  var SYNC_PBKDF2_ITERATIONS = 6e5;
  var SYNC_MAX_SAFE_URL_CHARS = 24e3;
  var SYNC_MAGIC = new Uint8Array([75, 90, 83, 1]);
  var FLAG_GZIP = 1;
  async function tryGzipCompress(bytes) {
    if (typeof CompressionStream !== "function") {
      return { bytes, compressed: false };
    }
    try {
      const cs = new CompressionStream("gzip");
      const writer = cs.writable.getWriter();
      writer.write(bytes);
      writer.close();
      const out = new Uint8Array(await new Response(cs.readable).arrayBuffer());
      if (out.length < bytes.length) {
        return { bytes: out, compressed: true };
      }
      return { bytes, compressed: false };
    } catch {
      return { bytes, compressed: false };
    }
  }
  async function tryGzipDecompress(bytes) {
    if (typeof DecompressionStream !== "function") {
      throw new KhaznaError(
        "SYNC_DECOMPRESS_UNSUPPORTED",
        "\u0627\u0644\u0645\u062A\u0635\u0641\u062D \u0627\u0644\u062D\u0627\u0644\u064A \u0644\u0627 \u064A\u062F\u0639\u0645 \u0641\u0643 \u0636\u063A\u0637 gzip \u0644\u062D\u0632\u0645\u0629 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629.",
        "This browser does not support gzip decompression for sync payloads."
      );
    }
    const ds = new DecompressionStream("gzip");
    const writer = ds.writable.getWriter();
    writer.write(bytes);
    writer.close();
    return new Uint8Array(await new Response(ds.readable).arrayBuffer());
  }
  function buildSyncAad(compressed) {
    return utf8Encode(`khazna:sync:v1|comp=${compressed ? "gzip" : "raw"}`);
  }
  function selectSyncRecords({
    sections = [],
    passwords = [],
    cards = [],
    notes = [],
    mode = "delta",
    sinceIso = null
  }) {
    const cutoffMs = mode === "delta" && sinceIso ? Date.parse(sinceIso) : 0;
    const isIncluded = (rec) => {
      if (!cutoffMs || Number.isNaN(cutoffMs)) return true;
      const ts = Date.parse(rec.updatedAt || rec.createdAt || "");
      return Number.isNaN(ts) || ts >= cutoffMs;
    };
    const selPasswords = passwords.filter((p) => !p.deletedAt && isIncluded(p));
    const selCards = cards.filter((c) => !c.deletedAt && isIncluded(c));
    const selNotes = notes.filter((n) => !n.deletedAt && isIncluded(n));
    const referencedSecIds = new Set(selPasswords.map((p) => p.data?.sectionId).filter(Boolean));
    const selSections = sections.filter(
      (s) => !s.deletedAt && (mode === "full" || isIncluded(s) || referencedSecIds.has(s.id))
    );
    return {
      v: 1,
      mode,
      since: mode === "delta" ? sinceIso : null,
      exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
      sections: selSections.map((s) => ({
        id: s.id,
        createdAt: s.createdAt,
        updatedAt: s.updatedAt,
        data: s.data
      })),
      passwords: selPasswords.map((p) => ({
        id: p.id,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
        data: p.data
      })),
      cards: selCards.map((c) => ({
        id: c.id,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt,
        data: c.data
      })),
      notes: selNotes.map((n) => ({
        id: n.id,
        createdAt: n.createdAt,
        updatedAt: n.updatedAt,
        data: n.data
      }))
    };
  }
  async function encodeSyncPackage({
    payload,
    passphrase,
    iterations = SYNC_PBKDF2_ITERATIONS,
    useCompression = true
  }) {
    if (!passphrase || String(passphrase).length < 4) {
      throw new KhaznaError(
        "SYNC_PASS_TOO_SHORT",
        "\u064A\u062C\u0628 \u0625\u062F\u062E\u0627\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0644\u0644\u0645\u0632\u0627\u0645\u0646\u0629 (\u0664 \u0623\u062D\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644\u060C \u0648\u064A\u064F\u0641\u0636\u0651\u0644 \u0627\u0633\u062A\u062E\u062F\u0627\u0645 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0642\u0648\u064A\u0629).",
        "Enter a sync passphrase (at least 4 characters; a strong passphrase is recommended)."
      );
    }
    const rawJson = utf8Encode(JSON.stringify(payload));
    const { bytes: bodyBytes, compressed } = useCompression ? await tryGzipCompress(rawJson) : { bytes: rawJson, compressed: false };
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const pwdBytes = utf8Encode(String(passphrase));
    let keyBytes = null;
    try {
      keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, iterations, 32);
      const aesKey = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
      );
      const aad = buildSyncAad(compressed);
      const ctBuf = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        aesKey,
        bodyBytes
      );
      const flags = new Uint8Array([compressed ? FLAG_GZIP : 0]);
      const packet = concatBytes(SYNC_MAGIC, flags, salt, iv, new Uint8Array(ctBuf));
      const token = bytesToBase64Url(packet);
      const code = `${SYNC_PREFIX}${token}`;
      return {
        code,
        token,
        compressed,
        byteLength: packet.length,
        counts: {
          sections: payload.sections?.length || 0,
          passwords: payload.passwords?.length || 0,
          cards: payload.cards?.length || 0,
          notes: payload.notes?.length || 0
        }
      };
    } finally {
      zeroize(pwdBytes, rawJson, bodyBytes, keyBytes);
    }
  }
  function extractSyncTokenFromInput(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) return "";
    const hashIdx = trimmed.indexOf("#");
    if (hashIdx !== -1) {
      const frag = trimmed.slice(hashIdx + 1);
      const params = new URLSearchParams(frag);
      const fromParam = params.get("sync");
      if (fromParam) return fromParam.replace(/\s+/g, "");
    }
    if (trimmed.startsWith(SYNC_HASH_KEY)) {
      return trimmed.slice(SYNC_HASH_KEY.length).replace(/\s+/g, "");
    }
    if (trimmed.toUpperCase().startsWith(SYNC_PREFIX)) {
      return trimmed.slice(SYNC_PREFIX.length).replace(/\s+/g, "");
    }
    return trimmed.replace(/\s+/g, "");
  }
  function buildSyncLink(baseUrl, token) {
    const cleanBase = String(baseUrl || "").split("#")[0].split("?")[0];
    const url = `${cleanBase}#sync=${token}`;
    return {
      url,
      length: url.length,
      fitsUrl: url.length <= SYNC_MAX_SAFE_URL_CHARS
    };
  }
  async function decodeSyncPackage({
    input,
    passphrase,
    iterations = SYNC_PBKDF2_ITERATIONS
  }) {
    const token = extractSyncTokenFromInput(input);
    if (!token) {
      throw new KhaznaError(
        "SYNC_EMPTY",
        "\u064A\u0631\u062C\u0649 \u0644\u0635\u0642 \u0643\u0648\u062F \u0623\u0648 \u0631\u0627\u0628\u0637 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 \u0623\u0648\u0644\u0627\u064B.",
        "Please paste an encrypted sync code or link first."
      );
    }
    if (!passphrase) {
      throw new KhaznaError(
        "SYNC_PASS_REQUIRED",
        "\u064A\u0631\u062C\u0649 \u0625\u062F\u062E\u0627\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u0644\u0641\u0643 \u0627\u0644\u062A\u0634\u0641\u064A\u0631.",
        "Please enter the sync passphrase to decrypt."
      );
    }
    let packet;
    try {
      packet = base64UrlToBytes(token);
    } catch {
      throw new KhaznaError(
        "SYNC_INVALID_FORMAT",
        "\u062A\u0646\u0633\u064A\u0642 \u0643\u0648\u062F \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u063A\u064A\u0631 \u0635\u0627\u0644\u062D \u0623\u0648 \u0646\u0627\u0642\u0635.",
        "Sync code format is invalid or truncated."
      );
    }
    if (packet.length < 4 + 1 + 16 + 12 + 16 || packet[0] !== SYNC_MAGIC[0] || packet[1] !== SYNC_MAGIC[1] || packet[2] !== SYNC_MAGIC[2] || packet[3] !== SYNC_MAGIC[3]) {
      throw new KhaznaError(
        "SYNC_INVALID_MAGIC",
        "\u0647\u0630\u0627 \u0627\u0644\u0643\u0648\u062F \u0644\u064A\u0633 \u062D\u0632\u0645\u0629 \u0645\u0632\u0627\u0645\u0646\u0629 \u0635\u0627\u0644\u062D\u0629 \u0645\u0646 \u062E\u0632\u0646\u0629.",
        "This code is not a valid Khazna sync package."
      );
    }
    const flags = packet[4];
    const compressed = Boolean(flags & FLAG_GZIP);
    const salt = packet.subarray(5, 21);
    const iv = packet.subarray(21, 33);
    const ciphertext = packet.subarray(33);
    const pwdBytes = utf8Encode(String(passphrase));
    let keyBytes = null;
    let plainBytes = null;
    try {
      keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, iterations, 32);
      const aesKey = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
      const aad = buildSyncAad(compressed);
      let decryptedBuf;
      try {
        decryptedBuf = await globalThis.crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
          aesKey,
          ciphertext
        );
      } catch {
        throw new KhaznaError(
          "SYNC_DECRYPT_FAILED",
          "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629 \u0623\u0648 \u062A\u0645 \u0627\u0644\u062A\u0644\u0627\u0639\u0628 \u0628\u0627\u0644\u0643\u0648\u062F.",
          "Incorrect sync passphrase or tampered sync code."
        );
      }
      plainBytes = compressed ? await tryGzipDecompress(new Uint8Array(decryptedBuf)) : new Uint8Array(decryptedBuf);
      const parsed = JSON.parse(utf8Decode(plainBytes));
      if (!parsed || parsed.v !== 1) {
        throw new KhaznaError(
          "SYNC_UNSUPPORTED_VERSION",
          "\u0625\u0635\u062F\u0627\u0631 \u062D\u0632\u0645\u0629 \u0627\u0644\u0645\u0632\u0627\u0645\u0646\u0629 \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645.",
          "Unsupported sync package version."
        );
      }
      return parsed;
    } finally {
      zeroize(pwdBytes, keyBytes, plainBytes);
    }
  }
  function normText(v) {
    return String(v || "").trim().toLowerCase();
  }
  function naturalKey(type, data = {}) {
    if (type === "section") return `sec:${normText(data.name)}`;
    if (type === "password") return `pwd:${normText(data.title)}|${normText(data.username)}|${normText(data.url)}`;
    if (type === "card") {
      const digits = String(data.number || "").replace(/\D/g, "");
      const last4 = digits.slice(-4) || String(data.last4 || "");
      return `crd:${normText(data.title)}|${last4}`;
    }
    if (type === "note") return `not:${normText(data.title)}`;
    return "";
  }
  function stableDataEquals(a, b) {
    return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  }
  function parseTs(iso) {
    const n = Date.parse(iso || "");
    return Number.isNaN(n) ? 0 : n;
  }
  function planSyncMerge({
    incoming,
    localSections = [],
    localPasswords = [],
    localCards = [],
    localNotes = [],
    strategy = "smart"
    // 'smart' | 'add-only'
  }) {
    const sectionIdMap = /* @__PURE__ */ new Map();
    const sectionActions = [];
    const localSecById = new Map(localSections.map((s) => [s.id, s]));
    const localSecByKey = new Map(localSections.map((s) => [naturalKey("section", s.data), s]));
    for (const inc of incoming.sections || []) {
      const match = localSecById.get(inc.id) || localSecByKey.get(naturalKey("section", inc.data));
      if (!match) {
        const newId = inc.id || randomId("sec");
        sectionIdMap.set(inc.id, newId);
        sectionActions.push({ action: "add", id: newId, data: inc.data, updatedAt: inc.updatedAt });
      } else {
        sectionIdMap.set(inc.id, match.id);
        if (strategy === "smart" && parseTs(inc.updatedAt) > parseTs(match.updatedAt) && !stableDataEquals(inc.data, match.data)) {
          sectionActions.push({ action: "update", id: match.id, data: inc.data, updatedAt: inc.updatedAt });
        } else {
          sectionActions.push({ action: "unchanged", id: match.id });
        }
      }
    }
    const planType = (type, incList, localList, transformData = (d) => d) => {
      const byId = new Map(localList.map((r) => [r.id, r]));
      const byKey = new Map(localList.map((r) => [naturalKey(type, r.data), r]));
      const actions = [];
      for (const inc of incList || []) {
        const data = transformData(inc.data || {});
        const key = naturalKey(type, data);
        const match = byId.get(inc.id) || (key ? byKey.get(key) : null);
        if (!match) {
          actions.push({
            action: "add",
            id: inc.id || randomId(type.slice(0, 3)),
            data,
            createdAt: inc.createdAt,
            updatedAt: inc.updatedAt
          });
        } else if (strategy === "smart" && parseTs(inc.updatedAt) > parseTs(match.updatedAt) && !stableDataEquals(data, match.data)) {
          actions.push({
            action: "update",
            id: match.id,
            data,
            createdAt: match.createdAt,
            updatedAt: inc.updatedAt
          });
        } else {
          actions.push({ action: "unchanged", id: match.id });
        }
      }
      return actions;
    };
    const passwordActions = planType("password", incoming.passwords, localPasswords, (d) => ({
      ...d,
      sectionId: d.sectionId ? sectionIdMap.get(d.sectionId) || d.sectionId : null
    }));
    const cardActions = planType("card", incoming.cards, localCards);
    const noteActions = planType("note", incoming.notes, localNotes);
    const count = (arr, kind) => arr.filter((x) => x.action === kind).length;
    return {
      mode: incoming.mode || "full",
      exportedAt: incoming.exportedAt || null,
      sections: sectionActions,
      passwords: passwordActions,
      cards: cardActions,
      notes: noteActions,
      summary: {
        added: count(sectionActions, "add") + count(passwordActions, "add") + count(cardActions, "add") + count(noteActions, "add"),
        updated: count(sectionActions, "update") + count(passwordActions, "update") + count(cardActions, "update") + count(noteActions, "update"),
        unchanged: count(sectionActions, "unchanged") + count(passwordActions, "unchanged") + count(cardActions, "unchanged") + count(noteActions, "unchanged"),
        passwordsAdded: count(passwordActions, "add"),
        passwordsUpdated: count(passwordActions, "update"),
        cardsAdded: count(cardActions, "add"),
        cardsUpdated: count(cardActions, "update"),
        notesAdded: count(noteActions, "add"),
        notesUpdated: count(noteActions, "update")
      }
    };
  }
  async function applySyncMerge({ session: session2, plan }) {
    const itemsToEncrypt = [];
    for (const s of plan.sections) {
      if (s.action === "add" || s.action === "update") {
        itemsToEncrypt.push({ type: "section", id: s.id, data: s.data, createdAt: s.createdAt });
      }
    }
    for (const p of plan.passwords) {
      if (p.action === "add" || p.action === "update") {
        itemsToEncrypt.push({ type: "password", id: p.id, data: p.data, createdAt: p.createdAt });
      }
    }
    for (const c of plan.cards) {
      if (c.action === "add" || c.action === "update") {
        itemsToEncrypt.push({ type: "card", id: c.id, data: c.data, createdAt: c.createdAt });
      }
    }
    for (const n of plan.notes) {
      if (n.action === "add" || n.action === "update") {
        itemsToEncrypt.push({ type: "note", id: n.id, data: n.data, createdAt: n.createdAt });
      }
    }
    let snapshotId = null;
    if (itemsToEncrypt.length > 0) {
      const encryptedBatch = await session2.encryptBatchForAtomicWrite(itemsToEncrypt);
      snapshotId = await session2.storage.atomicOperationWithSnapshot({
        reason: "device-sync",
        putRecords: encryptedBatch
      });
    }
    await session2.updateSettings({ lastSyncAt: (/* @__PURE__ */ new Date()).toISOString() });
    return {
      snapshotId,
      appliedCount: itemsToEncrypt.length,
      summary: plan.summary
    };
  }

  // src/storage/idb.js
  var DB_NAME = "khazna_vault_db";
  var DB_VERSION = 1;
  var MAX_SNAPSHOTS = 5;
  var STORES = Object.freeze({
    META: "meta",
    RECORDS: "records",
    SNAPSHOTS: "snapshots"
  });
  var DEFAULT_SETTINGS = Object.freeze({
    lang: "ar",
    theme: "dark",
    autoLockSec: 120,
    bgGraceSec: 15,
    clipboardClearSec: 30,
    copyComboMode: "two-step",
    reauthSensitive: true,
    lowEndBlur: "auto",
    lastBackupAt: null,
    backupReminderDays: 7,
    lastHealthCheck: null,
    onboardingDone: false
  });
  function structuredCloneSafe(val) {
    if (typeof structuredClone === "function") return structuredClone(val);
    return JSON.parse(JSON.stringify(val));
  }
  function normalizeQuotaError(err) {
    if (err?.name === "QuotaExceededError" || err?.code === 22 || /quota/i.test(String(err?.message || ""))) {
      return new KhaznaError(
        "STORAGE_QUOTA_EXCEEDED",
        "\u0645\u0633\u0627\u062D\u0629 \u0627\u0644\u062A\u062E\u0632\u064A\u0646 \u0639\u0644\u0649 \u062C\u0647\u0627\u0632\u0643 \u0645\u0645\u062A\u0644\u0626\u0629. \u0627\u062D\u0630\u0641 \u0628\u0639\u0636 \u0627\u0644\u0644\u0642\u0637\u0627\u062A \u0627\u0644\u0642\u062F\u064A\u0645\u0629 \u0623\u0648 \u0641\u0631\u0651\u063A \u0645\u0633\u0627\u062D\u0629 \u062B\u0645 \u062D\u0627\u0648\u0644 \u0645\u062C\u062F\u062F\u0627\u064B.",
        "Device storage quota exceeded. Free space or clear old snapshots and retry.",
        err
      );
    }
    return err;
  }
  function createMemoryBackend() {
    const stores = {
      [STORES.META]: /* @__PURE__ */ new Map(),
      [STORES.RECORDS]: /* @__PURE__ */ new Map(),
      [STORES.SNAPSHOTS]: /* @__PURE__ */ new Map()
    };
    return {
      kind: "memory",
      async transaction(storeNames, mode, fn) {
        const backup = mode === "readwrite" ? Object.fromEntries(
          storeNames.map((name) => [
            name,
            new Map(Array.from(stores[name].entries(), ([k, v]) => [k, structuredCloneSafe(v)]))
          ])
        ) : null;
        const txApi = {
          get: async (store, key) => {
            const val = stores[store].get(key);
            return val === void 0 ? void 0 : structuredCloneSafe(val);
          },
          getAll: async (store) => {
            return Array.from(stores[store].values(), (v) => structuredCloneSafe(v));
          },
          put: async (store, value, key) => {
            const k = key !== void 0 ? key : value.key ?? value.id;
            stores[store].set(k, structuredCloneSafe(value));
          },
          delete: async (store, key) => {
            stores[store].delete(key);
          },
          clear: async (store) => {
            stores[store].clear();
          }
        };
        try {
          return await fn(txApi);
        } catch (err) {
          if (backup) {
            for (const name of storeNames) {
              stores[name] = backup[name];
            }
          }
          throw normalizeQuotaError(err);
        }
      },
      async close() {
      }
    };
  }
  function createIndexedDbBackend(dbName = DB_NAME) {
    let dbPromise = null;
    function openDb() {
      if (dbPromise) return dbPromise;
      dbPromise = new Promise((resolve, reject) => {
        const req = globalThis.indexedDB.open(dbName, DB_VERSION);
        req.onupgradeneeded = (event) => {
          const db = req.result;
          const oldVersion = event.oldVersion;
          if (oldVersion < 1) {
            if (!db.objectStoreNames.contains(STORES.META)) {
              db.createObjectStore(STORES.META, { keyPath: "key" });
            }
            if (!db.objectStoreNames.contains(STORES.RECORDS)) {
              const recStore = db.createObjectStore(STORES.RECORDS, { keyPath: "id" });
              recStore.createIndex("by_type", "type", { unique: false });
              recStore.createIndex("by_updatedAt", "updatedAt", { unique: false });
            }
            if (!db.objectStoreNames.contains(STORES.SNAPSHOTS)) {
              const snapStore = db.createObjectStore(STORES.SNAPSHOTS, { keyPath: "id" });
              snapStore.createIndex("by_createdAt", "createdAt", { unique: false });
            }
          }
        };
        req.onsuccess = () => {
          const db = req.result;
          db.onversionchange = () => {
            db.close();
            dbPromise = null;
          };
          resolve(db);
        };
        req.onerror = () => {
          dbPromise = null;
          reject(new KhaznaError(
            "IDB_OPEN_FAILED",
            "\u062A\u0639\u0630\u0651\u0631 \u0641\u062A\u062D \u0642\u0627\u0639\u062F\u0629 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0627\u0644\u0645\u062D\u0644\u064A\u0629 (IndexedDB). \u062A\u0623\u0643\u062F \u0645\u0646 \u0639\u062F\u0645 \u062A\u0641\u0639\u064A\u0644 \u0627\u0644\u062A\u0635\u0641\u062D \u0627\u0644\u062E\u0641\u064A \u0627\u0644\u0645\u0642\u064A\u0651\u062F.",
            "Failed to open IndexedDB database.",
            req.error
          ));
        };
        req.onblocked = () => {
          reject(new KhaznaError(
            "IDB_BLOCKED",
            "\u0642\u0627\u0639\u062F\u0629 \u0627\u0644\u0628\u064A\u0627\u0646\u0627\u062A \u0645\u0641\u062A\u0648\u062D\u0629 \u0641\u064A \u062A\u0628\u0648\u064A\u0628 \u0622\u062E\u0631 \u2014 \u0623\u063A\u0644\u0650\u0642 \u0627\u0644\u062A\u0628\u0648\u064A\u0628\u0627\u062A \u0627\u0644\u0623\u062E\u0631\u0649 \u062B\u0645 \u0623\u0639\u062F \u0627\u0644\u0645\u062D\u0627\u0648\u0644\u0629.",
            "IndexedDB upgrade blocked by another open tab."
          ));
        };
      });
      return dbPromise;
    }
    function reqToPromise(request) {
      return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(normalizeQuotaError(request.error));
      });
    }
    return {
      kind: "indexeddb",
      async transaction(storeNames, mode, fn) {
        const db = await openDb();
        return new Promise((resolve, reject) => {
          const tx = db.transaction(storeNames, mode);
          let fnResult;
          let fnError = null;
          let settled = false;
          const txApi = {
            get: (store, key) => reqToPromise(tx.objectStore(store).get(key)),
            getAll: (store) => reqToPromise(tx.objectStore(store).getAll()),
            put: (store, value) => reqToPromise(tx.objectStore(store).put(value)),
            delete: (store, key) => reqToPromise(tx.objectStore(store).delete(key)),
            clear: (store) => reqToPromise(tx.objectStore(store).clear())
          };
          tx.oncomplete = () => {
            if (settled) return;
            settled = true;
            resolve(fnResult);
          };
          tx.onerror = () => {
            if (settled) return;
            settled = true;
            reject(normalizeQuotaError(fnError || tx.error));
          };
          tx.onabort = () => {
            if (settled) return;
            settled = true;
            reject(normalizeQuotaError(fnError || tx.error || new Error("Transaction aborted")));
          };
          Promise.resolve().then(() => fn(txApi)).then((res) => {
            fnResult = res;
          }).catch((err) => {
            fnError = err;
            try {
              tx.abort();
            } catch {
            }
          });
        });
      },
      async close() {
        if (dbPromise) {
          const db = await dbPromise;
          db.close();
          dbPromise = null;
        }
      }
    };
  }
  var VaultStorage = class {
    constructor(opts = {}) {
      this.backend = opts.backend || (typeof globalThis.indexedDB !== "undefined" ? createIndexedDbBackend(DB_NAME) : createMemoryBackend());
      this.lockName = opts.lockName || "khazna-vault-write-lock";
      this.tabId = randomId("tab");
      this._localQueue = Promise.resolve();
      this._listeners = /* @__PURE__ */ new Set();
      if (typeof globalThis.BroadcastChannel === "function") {
        try {
          this._channel = new BroadcastChannel(opts.channelName || "khazna-vault-sync");
          this._channel.onmessage = (ev) => {
            const msg = ev.data;
            if (!msg || msg.tabId === this.tabId) return;
            for (const cb of this._listeners) {
              try {
                cb(msg);
              } catch {
              }
            }
          };
        } catch {
          this._channel = null;
        }
      } else {
        this._channel = null;
      }
    }
    onSyncEvent(listener) {
      this._listeners.add(listener);
      return () => this._listeners.delete(listener);
    }
    broadcast(type, detail = null) {
      if (!this._channel) return;
      try {
        this._channel.postMessage({ type, tabId: this.tabId, ts: Date.now(), detail });
      } catch {
      }
    }
    async close() {
      if (this._channel) {
        try {
          this._channel.close();
        } catch {
        }
        this._channel = null;
      }
      if (this.backend && typeof this.backend.close === "function") {
        await this.backend.close();
      }
    }
    async withWriteLock(fn) {
      const isOpaqueOrigin = typeof globalThis.location !== "undefined" && (globalThis.location.protocol === "file:" || globalThis.location.origin === "null");
      if (!isOpaqueOrigin && typeof globalThis.navigator?.locks?.request === "function") {
        try {
          return await globalThis.navigator.locks.request(this.lockName, { mode: "exclusive" }, fn);
        } catch (err) {
          if (err?.name !== "SecurityError" && err?.name !== "NotSupportedError") {
            throw err;
          }
        }
      }
      const prev = this._localQueue;
      let release;
      this._localQueue = new Promise((r) => {
        release = r;
      });
      await prev;
      try {
        return await fn();
      } finally {
        release();
      }
    }
    async requestPersistentStorage() {
      let persisted = false;
      try {
        if (typeof globalThis.navigator?.storage?.persisted === "function") {
          persisted = await globalThis.navigator.storage.persisted();
        }
        if (!persisted && typeof globalThis.navigator?.storage?.persist === "function") {
          persisted = await globalThis.navigator.storage.persist();
        }
      } catch {
        persisted = false;
      }
      return this.getStorageStatus(persisted);
    }
    async getStorageStatus(knownPersisted) {
      let persisted = Boolean(knownPersisted);
      let usageBytes = 0;
      let quotaBytes = 0;
      try {
        if (knownPersisted === void 0 && typeof globalThis.navigator?.storage?.persisted === "function") {
          persisted = await globalThis.navigator.storage.persisted();
        }
        if (typeof globalThis.navigator?.storage?.estimate === "function") {
          const est = await globalThis.navigator.storage.estimate();
          usageBytes = est.usage ?? 0;
          quotaBytes = est.quota ?? 0;
        }
      } catch {
      }
      const percentUsed = quotaBytes > 0 ? Math.min(100, Number((usageBytes / quotaBytes * 100).toFixed(2))) : 0;
      return { persisted, usageBytes, quotaBytes, percentUsed };
    }
    async getHeader() {
      return this.backend.transaction([STORES.META], "readonly", async (tx) => {
        const row = await tx.get(STORES.META, "header");
        return row ? row.value : null;
      });
    }
    async hasVault() {
      const header = await this.getHeader();
      return Boolean(header && header.vaultId);
    }
    async saveHeader(header) {
      return this.withWriteLock(async () => {
        await this.backend.transaction([STORES.META], "readwrite", async (tx) => {
          await tx.put(STORES.META, { key: "header", value: header });
        });
        this.broadcast("VAULT_UPDATED", { scope: "header" });
      });
    }
    async getSettings() {
      const saved = await this.backend.transaction([STORES.META], "readonly", async (tx) => {
        const row = await tx.get(STORES.META, "settings");
        return row ? row.value : null;
      });
      return { ...DEFAULT_SETTINGS, ...saved || {} };
    }
    async saveSettings(partial) {
      return this.withWriteLock(async () => {
        const merged = await this.backend.transaction([STORES.META], "readwrite", async (tx) => {
          const existing = (await tx.get(STORES.META, "settings"))?.value || {};
          const next = { ...DEFAULT_SETTINGS, ...existing, ...partial };
          await tx.put(STORES.META, { key: "settings", value: next });
          return next;
        });
        this.broadcast("VAULT_UPDATED", { scope: "settings" });
        return merged;
      });
    }
    async getRecord(id) {
      return this.backend.transaction(
        [STORES.RECORDS],
        "readonly",
        (tx) => tx.get(STORES.RECORDS, id)
      );
    }
    async getAllRecords(type = null) {
      const all = await this.backend.transaction(
        [STORES.RECORDS],
        "readonly",
        (tx) => tx.getAll(STORES.RECORDS)
      );
      return type ? all.filter((r) => r.type === type) : all;
    }
    async putRecord(envelope) {
      return this.withWriteLock(async () => {
        await this.backend.transaction([STORES.RECORDS], "readwrite", async (tx) => {
          await tx.put(STORES.RECORDS, envelope);
        });
        this.broadcast("VAULT_UPDATED", { scope: "record", id: envelope.id });
      });
    }
    async putRecordsBatch(envelopes) {
      if (!envelopes.length) return;
      return this.withWriteLock(async () => {
        await this.backend.transaction([STORES.RECORDS], "readwrite", async (tx) => {
          for (const env of envelopes) {
            await tx.put(STORES.RECORDS, env);
          }
        });
        this.broadcast("VAULT_UPDATED", { scope: "batch", count: envelopes.length });
      });
    }
    async deleteRecord(id) {
      return this.withWriteLock(async () => {
        await this.backend.transaction([STORES.RECORDS], "readwrite", async (tx) => {
          await tx.delete(STORES.RECORDS, id);
        });
        this.broadcast("VAULT_UPDATED", { scope: "delete", id });
      });
    }
    async deleteRecordsBatch(ids) {
      if (!ids.length) return;
      return this.withWriteLock(async () => {
        await this.backend.transaction([STORES.RECORDS], "readwrite", async (tx) => {
          for (const id of ids) {
            await tx.delete(STORES.RECORDS, id);
          }
        });
        this.broadcast("VAULT_UPDATED", { scope: "batch-delete", count: ids.length });
      });
    }
    async atomicOperationWithSnapshot({
      reason,
      newHeader = null,
      putRecords = [],
      deleteIds = [],
      replaceAllRecords = false
    }) {
      return this.withWriteLock(async () => {
        const snapshotId = randomId("snap");
        const now = (/* @__PURE__ */ new Date()).toISOString();
        await this.backend.transaction(
          [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
          "readwrite",
          async (tx) => {
            const currentHeader = (await tx.get(STORES.META, "header"))?.value || null;
            const currentRecords = await tx.getAll(STORES.RECORDS);
            if (currentHeader) {
              await tx.put(STORES.SNAPSHOTS, {
                id: snapshotId,
                reason,
                createdAt: now,
                recordCount: currentRecords.length,
                header: currentHeader,
                records: currentRecords
              });
              const allSnaps = await tx.getAll(STORES.SNAPSHOTS);
              allSnaps.sort((a, b) => a.createdAt < b.createdAt ? 1 : -1);
              for (let i = MAX_SNAPSHOTS; i < allSnaps.length; i++) {
                await tx.delete(STORES.SNAPSHOTS, allSnaps[i].id);
              }
            }
            if (replaceAllRecords) {
              await tx.clear(STORES.RECORDS);
            }
            for (const id of deleteIds) {
              await tx.delete(STORES.RECORDS, id);
            }
            for (const env of putRecords) {
              await tx.put(STORES.RECORDS, env);
            }
            if (newHeader) {
              await tx.put(STORES.META, { key: "header", value: newHeader });
            }
          }
        );
        this.broadcast("VAULT_UPDATED", { scope: "atomic", reason });
        return snapshotId;
      });
    }
    async createSnapshot(reason = "manual") {
      return this.withWriteLock(async () => {
        const id = randomId("snap");
        const now = (/* @__PURE__ */ new Date()).toISOString();
        await this.backend.transaction(
          [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
          "readwrite",
          async (tx) => {
            const header = (await tx.get(STORES.META, "header"))?.value;
            if (!header) return;
            const records = await tx.getAll(STORES.RECORDS);
            await tx.put(STORES.SNAPSHOTS, {
              id,
              reason,
              createdAt: now,
              recordCount: records.length,
              header,
              records
            });
            const allSnaps = await tx.getAll(STORES.SNAPSHOTS);
            allSnaps.sort((a, b) => a.createdAt < b.createdAt ? 1 : -1);
            for (let i = MAX_SNAPSHOTS; i < allSnaps.length; i++) {
              await tx.delete(STORES.SNAPSHOTS, allSnaps[i].id);
            }
          }
        );
        return id;
      });
    }
    async listSnapshots() {
      const snaps = await this.backend.transaction(
        [STORES.SNAPSHOTS],
        "readonly",
        (tx) => tx.getAll(STORES.SNAPSHOTS)
      );
      return snaps.sort((a, b) => a.createdAt < b.createdAt ? 1 : -1).map((s) => ({
        id: s.id,
        reason: s.reason,
        createdAt: s.createdAt,
        recordCount: s.recordCount
      }));
    }
    async restoreSnapshot(snapshotId) {
      return this.withWriteLock(async () => {
        await this.backend.transaction(
          [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
          "readwrite",
          async (tx) => {
            const target = await tx.get(STORES.SNAPSHOTS, snapshotId);
            if (!target) {
              throw new KhaznaError(
                "SNAPSHOT_NOT_FOUND",
                "\u0627\u0644\u0644\u0642\u0637\u0629 \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 \u0627\u0644\u0645\u0637\u0644\u0648\u0628\u0629 \u063A\u064A\u0631 \u0645\u0648\u062C\u0648\u062F\u0629.",
                "Requested encrypted snapshot was not found."
              );
            }
            const currentHeader = (await tx.get(STORES.META, "header"))?.value;
            const currentRecords = await tx.getAll(STORES.RECORDS);
            if (currentHeader) {
              await tx.put(STORES.SNAPSHOTS, {
                id: randomId("snap"),
                reason: "pre-restore",
                createdAt: (/* @__PURE__ */ new Date()).toISOString(),
                recordCount: currentRecords.length,
                header: currentHeader,
                records: currentRecords
              });
            }
            await tx.put(STORES.META, { key: "header", value: target.header });
            await tx.clear(STORES.RECORDS);
            for (const rec of target.records) {
              await tx.put(STORES.RECORDS, rec);
            }
            const allSnaps = await tx.getAll(STORES.SNAPSHOTS);
            allSnaps.sort((a, b) => a.createdAt < b.createdAt ? 1 : -1);
            for (let i = MAX_SNAPSHOTS; i < allSnaps.length; i++) {
              await tx.delete(STORES.SNAPSHOTS, allSnaps[i].id);
            }
          }
        );
        this.broadcast("VAULT_UPDATED", { scope: "restore-snapshot", snapshotId });
      });
    }
    async purgeExpiredTrash(days = 30) {
      const cutoff = Date.now() - days * 24 * 60 * 60 * 1e3;
      const all = await this.getAllRecords();
      const expiredIds = all.filter((r) => r.deletedAt && Date.parse(r.deletedAt) < cutoff).map((r) => r.id);
      if (expiredIds.length > 0) {
        await this.deleteRecordsBatch(expiredIds);
      }
      return expiredIds.length;
    }
    async runVaultHealthCheck(dek) {
      const header = await this.getHeader();
      if (!header) {
        throw new KhaznaError("NO_VAULT", "\u0644\u0627 \u062A\u0648\u062C\u062F \u062E\u0632\u0646\u0629 \u0645\u0647\u064A\u0651\u0623\u0629.", "No vault initialized.");
      }
      const envelopes = await this.getAllRecords();
      const corrupted = [];
      let valid = 0;
      let estimatedBytes = JSON.stringify(header).length;
      for (const env of envelopes) {
        estimatedBytes += JSON.stringify(env).length;
        try {
          await decryptRecord(dek, env, header.vaultId);
          valid++;
        } catch (err) {
          corrupted.push({
            id: env?.id || "unknown",
            type: env?.type || "unknown",
            code: err?.code || "DECRYPT_FAILED"
          });
        }
      }
      const report = {
        ok: corrupted.length === 0,
        total: envelopes.length,
        valid,
        corrupted,
        estimatedBytes,
        checkedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      await this.saveSettings({
        lastHealthCheck: {
          ok: report.ok,
          total: report.total,
          corruptedCount: corrupted.length,
          checkedAt: report.checkedAt
        }
      });
      return report;
    }
    async wipeAll({ wipeSettings = false } = {}) {
      return this.withWriteLock(async () => {
        await this.backend.transaction(
          [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
          "readwrite",
          async (tx) => {
            const settingsRow = wipeSettings ? null : await tx.get(STORES.META, "settings");
            await tx.clear(STORES.META);
            await tx.clear(STORES.RECORDS);
            await tx.clear(STORES.SNAPSHOTS);
            if (settingsRow) {
              await tx.put(STORES.META, {
                key: "settings",
                value: { ...settingsRow.value, onboardingDone: false, lastBackupAt: null }
              });
            }
          }
        );
        this.broadcast("VAULT_WIPED");
      });
    }
    async close() {
      if (this._channel) {
        this._channel.close();
        this._channel = null;
      }
      await this.backend.close();
    }
  };

  // src/domain/cards.js
  var CARD_BRANDS = Object.freeze([
    { id: "auto", labelAr: "\u0643\u0634\u0641 \u062A\u0644\u0642\u0627\u0626\u064A", labelEn: "Auto-detect" },
    { id: "visa", labelAr: "Visa", labelEn: "Visa" },
    { id: "mastercard", labelAr: "Mastercard", labelEn: "Mastercard" },
    { id: "meeza", labelAr: "\u0645\u064A\u0632\u0629 (Meeza)", labelEn: "Meeza" },
    { id: "amex", labelAr: "American Express", labelEn: "American Express" },
    { id: "discover", labelAr: "Discover", labelEn: "Discover" },
    { id: "unionpay", labelAr: "UnionPay", labelEn: "UnionPay" },
    { id: "other", labelAr: "\u0623\u062E\u0631\u0649", labelEn: "Other" }
  ]);
  var CARD_THEMES = Object.freeze([
    { id: "obsidian", labelAr: "\u0623\u0648\u0628\u0633\u064A\u062F\u064A\u0627\u0646 \u062F\u0627\u0643\u0646", labelEn: "Obsidian Glass" },
    { id: "aurora", labelAr: "\u0634\u0641\u0642 \u0623\u0632\u0631\u0642", labelEn: "Aurora Indigo" },
    { id: "emerald", labelAr: "\u0632\u0645\u0631\u062F\u064A", labelEn: "Emerald Vault" },
    { id: "sunset", labelAr: "\u063A\u0631\u0648\u0628 \u062F\u0627\u0641\u0626", labelEn: "Warm Sunset" },
    { id: "gold", labelAr: "\u0630\u0647\u0628\u064A \u0645\u0644\u0643\u064A", labelEn: "Royal Gold" },
    { id: "frost", labelAr: "\u0632\u062C\u0627\u062C \u062B\u0644\u062C\u064A", labelEn: "Frosted Glass" }
  ]);
  function normalizeCardInput(raw) {
    return String(raw || "").replace(/[\s\-]+/g, "").replace(/[•xX]/g, "*");
  }
  function digitsOnly(raw) {
    return String(raw || "").replace(/\D+/g, "");
  }
  function isPartialCardNumber(raw) {
    const norm = normalizeCardInput(raw);
    return norm.includes("*");
  }
  function validateLuhn(raw) {
    if (isPartialCardNumber(raw)) return null;
    const digits = digitsOnly(raw);
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (shouldDouble) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }
  function detectCardBrand(raw, manualOverride = "auto") {
    if (manualOverride && manualOverride !== "auto") return manualOverride;
    const norm = normalizeCardInput(raw);
    const prefix = norm.replace(/\*.*$/, "");
    if (!prefix) return "other";
    if (/^5078/.test(prefix)) return "meeza";
    if (/^4/.test(prefix)) return "visa";
    if (/^(5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(prefix)) return "mastercard";
    if (/^3[47]/.test(prefix)) return "amex";
    if (/^(6011|65|64[4-9])/.test(prefix)) return "discover";
    if (/^62/.test(prefix)) return "unionpay";
    return "other";
  }
  function formatCardNumber(raw, brand = null) {
    const norm = normalizeCardInput(raw);
    if (!norm) return "";
    const detected = brand || detectCardBrand(norm);
    const display = norm.replace(/\*/g, "\u2022");
    if (detected === "amex") {
      const p1 = display.slice(0, 4);
      const p2 = display.slice(4, 10);
      const p3 = display.slice(10, 15);
      return [p1, p2, p3].filter(Boolean).join(" ");
    }
    return display.replace(/(.{4})/g, "$1 ").trim();
  }
  function maskCardNumber(raw, brand = null) {
    const norm = normalizeCardInput(raw);
    if (!norm) return "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022";
    const detected = brand || detectCardBrand(norm);
    if (norm.includes("*")) {
      return formatCardNumber(norm, detected);
    }
    const len = norm.length;
    const last4 = norm.slice(-4);
    if (detected === "amex") {
      return `\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022\u2022\u2022 \u2022${last4}`;
    }
    const maskedLen = Math.max(12, len) - last4.length;
    const masked = "\u2022".repeat(maskedLen) + last4;
    return formatCardNumber(masked, detected);
  }
  function formatExpiry(raw) {
    const digits = digitsOnly(raw).slice(0, 4);
    if (digits.length <= 2) return digits;
    return `${digits.slice(0, 2)}/${digits.slice(2)}`;
  }
  function formatCardCopyAll(card, lang = "ar") {
    const brand = detectCardBrand(card.number, card.brandOverride);
    const lines = [];
    if (card.cardName) lines.push(`${lang === "ar" ? "\u0627\u0644\u0628\u0637\u0627\u0642\u0629" : "Card"}: ${card.cardName}`);
    if (card.bankName) lines.push(`${lang === "ar" ? "\u0627\u0644\u0628\u0646\u0643" : "Bank"}: ${card.bankName}`);
    if (card.holderName) lines.push(`${lang === "ar" ? "\u0627\u0644\u0627\u0633\u0645" : "Holder"}: ${card.holderName}`);
    if (card.number) lines.push(`${lang === "ar" ? "\u0627\u0644\u0631\u0642\u0645" : "Number"}: ${formatCardNumber(card.number, brand)}`);
    if (card.expiry) lines.push(`${lang === "ar" ? "\u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621" : "Expiry"}: ${card.expiry}`);
    if (card.cvv) lines.push(`CVV: ${card.cvv}`);
    if (card.pin) lines.push(`PIN: ${card.pin}`);
    return lines.join("\n");
  }

  // src/ui/dom.js
  var SVG_NS = "http://www.w3.org/2000/svg";
  var ACCENT_MAP = /* @__PURE__ */ new Map([
    ["#38bdf8", "accent-sky"],
    ["#10b981", "accent-emerald"],
    ["#a78bfa", "accent-violet"],
    ["#f59e0b", "accent-amber"],
    ["#f472b6", "accent-rose"],
    ["#2dd4bf", "accent-teal"],
    ["#fb7185", "accent-coral"],
    ["#94a3b8", "accent-slate"]
  ]);
  var SECTION_COLOR_OPTIONS = Object.freeze([
    { hex: "#38bdf8", cls: "accent-sky", nameAr: "\u0633\u0645\u0627\u0648\u064A", nameEn: "Sky" },
    { hex: "#10b981", cls: "accent-emerald", nameAr: "\u0632\u0645\u0631\u062F\u064A", nameEn: "Emerald" },
    { hex: "#a78bfa", cls: "accent-violet", nameAr: "\u0628\u0646\u0641\u0633\u062C\u064A", nameEn: "Violet" },
    { hex: "#f59e0b", cls: "accent-amber", nameAr: "\u0643\u0647\u0631\u0645\u0627\u0646\u064A", nameEn: "Amber" },
    { hex: "#f472b6", cls: "accent-rose", nameAr: "\u0648\u0631\u062F\u064A", nameEn: "Rose" },
    { hex: "#2dd4bf", cls: "accent-teal", nameAr: "\u0641\u064A\u0631\u0648\u0632\u064A", nameEn: "Teal" },
    { hex: "#fb7185", cls: "accent-coral", nameAr: "\u0645\u0631\u062C\u0627\u0646\u064A", nameEn: "Coral" }
  ]);
  function accentClassForHex(hex) {
    return ACCENT_MAP.get(String(hex || "").toLowerCase()) || "accent-sky";
  }
  function el(tag, attrs = null, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === void 0 || v === null || v === false) continue;
        if (k === "class" || k === "className") {
          node.className = String(v);
        } else if (k === "dataset" && typeof v === "object") {
          for (const [dk, dv] of Object.entries(v)) {
            if (dv !== void 0 && dv !== null) node.dataset[dk] = String(dv);
          }
        } else if (k.startsWith("on") && typeof v === "function") {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else if (k === "value" && "value" in node) {
          node.value = String(v);
        } else if (k === "checked" && "checked" in node) {
          node.checked = Boolean(v);
        } else if (k === "disabled" && "disabled" in node) {
          node.disabled = Boolean(v);
        } else if (k === "style") {
          continue;
        } else if (v === true) {
          node.setAttribute(k, "");
        } else {
          node.setAttribute(k, String(v));
        }
      }
    }
    appendChildren(node, children);
    return node;
  }
  function appendChildren(parent, children) {
    for (const child of children) {
      if (child === null || child === void 0 || child === false) continue;
      if (Array.isArray(child)) {
        appendChildren(parent, child);
      } else if (child instanceof Node) {
        parent.appendChild(child);
      } else {
        parent.appendChild(document.createTextNode(String(child)));
      }
    }
  }
  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }
  function svgEl(tag, attrs = {}, ...children) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === void 0 || v === null || k === "style") continue;
      node.setAttribute(k, String(v));
    }
    for (const child of children) {
      if (child instanceof Node) node.appendChild(child);
      else if (child !== null && child !== void 0) {
        node.appendChild(document.createTextNode(String(child)));
      }
    }
    return node;
  }
  var ICON_PATHS = {
    lock: [
      ["rect", { x: 3, y: 11, width: 18, height: 11, rx: 2, ry: 2 }],
      ["path", { d: "M7 11V7a5 5 0 0 1 10 0v4" }]
    ],
    key: [
      ["circle", { cx: 7.5, cy: 15.5, r: 4.5 }],
      ["path", { d: "m21 2-9.6 9.6" }],
      ["path", { d: "m15.5 7.5 3 3L22 7l-3-3" }]
    ],
    fingerprint: [
      ["path", { d: "M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" }],
      ["path", { d: "M14 13.12c0 2.38 0 6.38-1 8.88" }],
      ["path", { d: "M17.29 21.02c.12-.6.43-2.3.5-3.02" }],
      ["path", { d: "M2 12a10 10 0 0 1 18-6" }],
      ["path", { d: "M2 16h.01" }],
      ["path", { d: "M21.8 16c.2-2 .131-5.354 0-6" }],
      ["path", { d: "M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" }],
      ["path", { d: "M8.65 22c.21-.66.45-1.32.57-2" }],
      ["path", { d: "M9 6.8a6 6 0 0 1 9 5.2v2" }]
    ],
    card: [
      ["rect", { x: 2, y: 5, width: 20, height: 14, rx: 2 }],
      ["line", { x1: 2, y1: 10, x2: 22, y2: 10 }]
    ],
    note: [
      ["path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" }],
      ["polyline", { points: "14 2 14 8 20 8" }],
      ["line", { x1: 8, y1: 13, x2: 16, y2: 13 }],
      ["line", { x1: 8, y1: 17, x2: 13, y2: 17 }]
    ],
    chart: [
      ["path", { d: "M21.21 15.89A10 10 0 1 1 8 2.83" }],
      ["path", { d: "M22 12A10 10 0 0 0 12 2v10z" }]
    ],
    settings: [
      ["circle", { cx: 12, cy: 12, r: 3 }],
      ["path", { d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" }]
    ],
    copy: [
      ["rect", { x: 9, y: 9, width: 13, height: 13, rx: 2, ry: 2 }],
      ["path", { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" }]
    ],
    eye: [
      ["path", { d: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" }],
      ["circle", { cx: 12, cy: 12, r: 3 }]
    ],
    star: [
      ["polygon", { points: "12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" }]
    ],
    plus: [
      ["line", { x1: 12, y1: 5, x2: 12, y2: 19 }],
      ["line", { x1: 5, y1: 12, x2: 19, y2: 12 }]
    ],
    search: [
      ["circle", { cx: 11, cy: 11, r: 8 }],
      ["line", { x1: 21, y1: 21, x2: 16.65, y2: 16.65 }]
    ],
    trash: [
      ["polyline", { points: "3 6 5 6 21 6" }],
      ["path", { d: "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" }]
    ],
    edit: [
      ["path", { d: "M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" }],
      ["path", { d: "M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" }]
    ],
    shield: [
      ["path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }]
    ],
    flip: [
      ["polyline", { points: "17 1 21 5 17 9" }],
      ["path", { d: "M3 11V9a4 4 0 0 1 4-4h14" }],
      ["polyline", { points: "7 23 3 19 7 15" }],
      ["path", { d: "M21 13v2a4 4 0 0 1-4 4H3" }]
    ],
    close: [
      ["line", { x1: 18, y1: 6, x2: 6, y2: 18 }],
      ["line", { x1: 6, y1: 6, x2: 18, y2: 18 }]
    ],
    check: [
      ["polyline", { points: "20 6 9 17 4 12" }]
    ],
    refresh: [
      ["polyline", { points: "23 4 23 10 17 10" }],
      ["path", { d: "M20.49 15a9 9 0 1 1-2.12-9.36L23 10" }]
    ],
    download: [
      ["path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }],
      ["polyline", { points: "7 10 12 15 17 10" }],
      ["line", { x1: 12, y1: 15, x2: 12, y2: 3 }]
    ],
    upload: [
      ["path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }],
      ["polyline", { points: "17 8 12 3 7 8" }],
      ["line", { x1: 12, y1: 3, x2: 12, y2: 15 }]
    ],
    pin: [
      ["path", { d: "M12 17v5" }],
      ["path", { d: "M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16h14v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1z" }]
    ],
    link: [
      ["path", { d: "M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" }],
      ["path", { d: "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" }]
    ],
    share: [
      ["circle", { cx: 18, cy: 5, r: 3 }],
      ["circle", { cx: 6, cy: 12, r: 3 }],
      ["circle", { cx: 18, cy: 19, r: 3 }],
      ["line", { x1: 8.59, y1: 13.51, x2: 15.42, y2: 17.49 }],
      ["line", { x1: 15.41, y1: 6.51, x2: 8.59, y2: 10.49 }]
    ]
  };
  function svgIcon(name, size = 20, filled = false) {
    const shapes = ICON_PATHS[name] || ICON_PATHS.shield;
    return svgEl(
      "svg",
      {
        width: size,
        height: size,
        viewBox: "0 0 24 24",
        fill: filled ? "currentColor" : "none",
        stroke: "currentColor",
        "stroke-width": 2,
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
        "aria-hidden": "true"
      },
      ...shapes.map(([tag, attrs]) => svgEl(tag, attrs))
    );
  }
  function emvChipSvg() {
    return svgEl(
      "svg",
      { width: 42, height: 32, viewBox: "0 0 42 32", "aria-hidden": "true" },
      svgEl("rect", { x: 1, y: 1, width: 40, height: 30, rx: 6, fill: "#e2c275", stroke: "#b48a34", "stroke-width": 1.5 }),
      svgEl("line", { x1: 1, y1: 11, x2: 41, y2: 11, stroke: "#926c21", "stroke-width": 1.2 }),
      svgEl("line", { x1: 1, y1: 21, x2: 41, y2: 21, stroke: "#926c21", "stroke-width": 1.2 }),
      svgEl("line", { x1: 15, y1: 1, x2: 15, y2: 31, stroke: "#926c21", "stroke-width": 1.2 }),
      svgEl("line", { x1: 27, y1: 1, x2: 27, y2: 31, stroke: "#926c21", "stroke-width": 1.2 })
    );
  }
  function contactlessSvg() {
    return svgEl(
      "svg",
      { width: 22, height: 22, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "aria-hidden": "true" },
      svgEl("path", { d: "M8.5 16.5a5 5 0 0 1 0-9" }),
      svgEl("path", { d: "M12 19a9 9 0 0 1 0-14" }),
      svgEl("path", { d: "M15.5 21.5a13 13 0 0 1 0-19" })
    );
  }
  function brandLogoSvg(brand) {
    if (brand === "mastercard") {
      return svgEl(
        "svg",
        { width: 48, height: 30, viewBox: "0 0 48 30", "aria-label": "Mastercard" },
        svgEl("circle", { cx: 18, cy: 15, r: 11, fill: "#eb001b", opacity: "0.92" }),
        svgEl("circle", { cx: 30, cy: 15, r: 11, fill: "#f79e1b", opacity: "0.88" })
      );
    }
    if (brand === "visa") {
      return svgEl(
        "svg",
        { width: 54, height: 26, viewBox: "0 0 54 26", "aria-label": "Visa" },
        svgEl("text", { x: 2, y: 20, fill: "#ffffff", "font-size": 18, "font-weight": 800, "font-style": "italic", "letter-spacing": "1" }, "VISA")
      );
    }
    if (brand === "meeza") {
      return svgEl(
        "svg",
        { width: 64, height: 26, viewBox: "0 0 64 26", "aria-label": "Meeza" },
        svgEl("rect", { x: 1, y: 3, width: 62, height: 20, rx: 6, fill: "rgba(16,185,129,0.28)", stroke: "#34d399", "stroke-width": 1.2 }),
        svgEl("text", { x: 32, y: 17, fill: "#ffffff", "font-size": 11, "font-weight": 800, "text-anchor": "middle" }, "MEEZA")
      );
    }
    if (brand === "amex") {
      return svgEl(
        "svg",
        { width: 58, height: 26, viewBox: "0 0 58 26", "aria-label": "American Express" },
        svgEl("rect", { x: 1, y: 3, width: 56, height: 20, rx: 5, fill: "rgba(56,189,248,0.28)", stroke: "#7dd3fc", "stroke-width": 1.2 }),
        svgEl("text", { x: 29, y: 17, fill: "#ffffff", "font-size": 11, "font-weight": 800, "text-anchor": "middle" }, "AMEX")
      );
    }
    if (brand === "discover") {
      return svgEl(
        "svg",
        { width: 70, height: 26, viewBox: "0 0 70 26", "aria-label": "Discover" },
        svgEl("text", { x: 35, y: 18, fill: "#fbbf24", "font-size": 12, "font-weight": 800, "text-anchor": "middle" }, "DISCOVER")
      );
    }
    if (brand === "unionpay") {
      return svgEl(
        "svg",
        { width: 66, height: 26, viewBox: "0 0 66 26", "aria-label": "UnionPay" },
        svgEl("rect", { x: 1, y: 3, width: 64, height: 20, rx: 5, fill: "rgba(244,63,94,0.25)", stroke: "#fda4af", "stroke-width": 1 }),
        svgEl("text", { x: 33, y: 17, fill: "#ffffff", "font-size": 10, "font-weight": 700, "text-anchor": "middle" }, "UnionPay")
      );
    }
    return svgEl(
      "svg",
      { width: 42, height: 24, viewBox: "0 0 42 24", "aria-label": "Card" },
      svgEl("rect", { x: 2, y: 3, width: 38, height: 18, rx: 4, fill: "none", stroke: "rgba(255,255,255,0.65)", "stroke-width": 1.5 }),
      svgEl("line", { x1: 2, y1: 9, x2: 40, y2: 9, stroke: "rgba(255,255,255,0.65)", "stroke-width": 1.5 })
    );
  }
  function triggerHaptic(pattern = 18) {
    try {
      if (typeof navigator !== "undefined" && typeof navigator.vibrate === "function") {
        navigator.vibrate(pattern);
      }
    } catch {
    }
  }
  function showToast(message, kind = "info", durationMs = 2800) {
    const root = document.getElementById("toast-root");
    if (!root) return;
    const toast = el(
      "div",
      { class: `toast toast-${kind}`, role: "status" },
      kind === "success" ? svgIcon("check", 16) : null,
      el("span", null, message)
    );
    root.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, durationMs);
  }
  function openBottomSheet({ title, content, onClose }) {
    const modalRoot = document.getElementById("modal-root");
    if (!modalRoot) return { close: () => {
    } };
    const close = () => {
      document.removeEventListener("keydown", onKey);
      backdrop.remove();
      if (typeof onClose === "function") onClose();
    };
    const onKey = (e) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("keydown", onKey);
    const closeBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-icon btn-ghost",
        "aria-label": "Close",
        onClick: close
      },
      svgIcon("close", 20)
    );
    const panel = el(
      "div",
      { class: "sheet-panel", role: "dialog", "aria-modal": "true", "aria-label": title },
      el("div", { class: "sheet-header" }, el("h2", { class: "sheet-title" }, title), closeBtn),
      content
    );
    const backdrop = el(
      "div",
      {
        class: "sheet-backdrop",
        onClick: (e) => {
          if (e.target === backdrop) close();
        }
      },
      panel
    );
    modalRoot.appendChild(backdrop);
    return { close, panel };
  }
  function attachHoldToReveal(button, { onReveal, onHide, autoHideMs = 1e4 }) {
    let hideTimer = null;
    let revealed = false;
    const reveal = () => {
      if (!revealed) {
        revealed = true;
        onReveal();
      }
      if (hideTimer) clearTimeout(hideTimer);
      hideTimer = setTimeout(hide, autoHideMs);
    };
    const hide = () => {
      if (hideTimer) {
        clearTimeout(hideTimer);
        hideTimer = null;
      }
      if (revealed) {
        revealed = false;
        onHide();
      }
    };
    button.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      reveal();
    });
    button.addEventListener("pointerup", hide);
    button.addEventListener("pointercancel", hide);
    button.addEventListener("pointerleave", hide);
    button.addEventListener("click", (e) => {
      if (e.detail === 0) {
        if (revealed) hide();
        else reveal();
      }
    });
  }
  function requestReauth({ session: session2, lang }) {
    if (!session2.settings?.reauthSensitive) {
      return Promise.resolve(true);
    }
    return new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        sheet.close();
        resolve(ok);
      };
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const pwdInput = el("input", {
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: t(lang, "masterPasswordLabel")
      });
      const submitBtn = el("button", { type: "submit", class: "btn btn-primary btn-block" }, t(lang, "confirmBtn"));
      const bioState = session2.getBiometricState();
      const bioBtn = bioState.enabled ? el(
        "button",
        {
          type: "button",
          class: "btn btn-block",
          onClick: async () => {
            errBox.classList.add("hidden");
            try {
              await session2.verifyReauth({ useBiometric: true });
              finish(true);
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove("hidden");
            }
          }
        },
        svgIcon("fingerprint", 18),
        t(lang, "unlockWithFingerprint")
      ) : null;
      const form = el(
        "form",
        {
          onSubmit: async (e) => {
            e.preventDefault();
            errBox.classList.add("hidden");
            submitBtn.disabled = true;
            try {
              await session2.verifyReauth({ masterPassword: pwdInput.value });
              pwdInput.value = "";
              finish(true);
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove("hidden");
            } finally {
              submitBtn.disabled = false;
            }
          }
        },
        el("p", { class: "settings-row-desc" }, t(lang, "reauthSubtitle")),
        errBox,
        el("div", { class: "field" }, pwdInput),
        el("div", { class: "settings-group" }, submitBtn, bioBtn)
      );
      const sheet = openBottomSheet({
        title: t(lang, "reauthTitle"),
        content: form,
        onClose: () => {
          if (!settled) {
            settled = true;
            resolve(false);
          }
        }
      });
      setTimeout(() => pwdInput.focus(), 60);
    });
  }
  function animateCounter(node, target) {
    const num = Number(target) || 0;
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || num === 0) {
      node.textContent = String(num);
      return;
    }
    const duration = 420;
    const start = performance.now();
    const step = (ts) => {
      const progress = Math.min(1, (ts - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      node.textContent = String(Math.round(num * eased));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // src/ui/cards-view.js
  function build3DBankCardWidget({
    data,
    lang,
    masked = true,
    isPreview = false,
    revealedSecrets = { number: false, cvv: false, pin: false }
  }) {
    const brand = detectCardBrand(data.number, data.brandOverride);
    const theme = data.theme || "obsidian";
    const numberDisplay = isPreview ? data.number ? formatCardNumber(data.number, brand) : "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022" : revealedSecrets.number || !masked ? data.number ? formatCardNumber(data.number, brand) : "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022" : maskCardNumber(data.number, brand);
    const cvvDisplay = isPreview || revealedSecrets.cvv || !masked ? data.cvv || "\u2022\u2022\u2022" : "\u2022\u2022\u2022";
    const pinDisplay = isPreview || revealedSecrets.pin || !masked ? data.pin || "\u2022\u2022\u2022\u2022" : "\u2022\u2022\u2022\u2022";
    const brandSlot = el("div", { class: "card-brand-slot" }, brandLogoSvg(brand));
    const labelNode = el("div", { class: "card-label-name" }, data.cardName || (lang === "en" ? "Card Label" : "\u0627\u0633\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629"));
    const bankNode = el("div", { class: "card-bank-name" }, data.bankName || (lang === "en" ? "Bank" : "\u0627\u0644\u0628\u0646\u0643"));
    const numberNode = el("div", { class: "card-number-embossed", "data-testid": isPreview ? "preview-card-number" : void 0 }, numberDisplay);
    const holderNode = el("div", { class: "card-meta-val ltr-value" }, (data.holderName || "CARDHOLDER NAME").toUpperCase());
    const expiryNode = el("div", { class: "card-meta-val ltr-value" }, data.expiry || "MM/YY");
    const cvvNode = el("span", { class: "ltr-inline mono" }, cvvDisplay);
    const pinNode = el("span", { class: "ltr-inline mono" }, pinDisplay);
    const front = el(
      "div",
      { class: "bank-card-face bank-card-front" },
      el(
        "div",
        { class: "card-top-row" },
        el("div", { class: "card-label-block" }, labelNode, bankNode),
        brandSlot
      ),
      el("div", { class: "card-chip-row" }, emvChipSvg(), contactlessSvg()),
      numberNode,
      el(
        "div",
        { class: "card-bottom-row" },
        el("div", { class: "card-meta-col" }, el("span", { class: "card-meta-label" }, "CARDHOLDER"), holderNode),
        el("div", { class: "card-meta-col" }, el("span", { class: "card-meta-label" }, "EXPIRES"), expiryNode)
      )
    );
    const back = el(
      "div",
      { class: "bank-card-face bank-card-back" },
      el("div", { class: "card-mag-stripe", "aria-hidden": "true" }),
      el(
        "div",
        { class: "card-back-body" },
        el(
          "div",
          { class: "card-signature-strip" },
          el("span", null, "CVV / CVC"),
          cvvNode
        ),
        el(
          "div",
          { class: "card-back-pin-row" },
          el("span", null, "PIN"),
          pinNode
        )
      )
    );
    const inner3d = el("div", { class: "bank-card-3d" }, front, back);
    const scene = el("div", { class: `bank-card-scene card-theme-${theme}` }, inner3d);
    return {
      scene,
      inner3d,
      setFlipped: (flipped) => inner3d.classList.toggle("is-flipped", Boolean(flipped)),
      toggleFlip: () => inner3d.classList.toggle("is-flipped"),
      updateLive: (next) => {
        const b = detectCardBrand(next.number, next.brandOverride);
        scene.className = `bank-card-scene card-theme-${next.theme || "obsidian"}`;
        clearNode(brandSlot);
        brandSlot.appendChild(brandLogoSvg(b));
        labelNode.textContent = next.cardName || (lang === "en" ? "Card Label" : "\u0627\u0633\u0645 \u0627\u0644\u0628\u0637\u0627\u0642\u0629");
        bankNode.textContent = next.bankName || (lang === "en" ? "Bank" : "\u0627\u0644\u0628\u0646\u0643");
        numberNode.textContent = next.number ? formatCardNumber(next.number, b) : "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022";
        holderNode.textContent = (next.holderName || "CARDHOLDER NAME").toUpperCase();
        expiryNode.textContent = next.expiry || "MM/YY";
        cvvNode.textContent = next.cvv || "\u2022\u2022\u2022";
        pinNode.textContent = next.pin || "\u2022\u2022\u2022\u2022";
      },
      setNumberText: (txt) => {
        numberNode.textContent = txt;
      },
      setCvvText: (txt) => {
        cvvNode.textContent = txt;
      },
      setPinText: (txt) => {
        pinNode.textContent = txt;
      }
    };
  }
  function renderCardsView({ session: session2, lang, cards, onRefresh }) {
    const container = el("div", { class: "settings-group view-enter" });
    const copySecret = async (val, label) => {
      if (!val) return;
      try {
        await session2.clipboard.copySecret(val, session2.settings?.clipboardClearSec ?? 30);
        triggerHaptic();
        showToast(`${t(lang, "copiedToast")}: ${label}`, "success");
      } catch (err) {
        showToast(formatError(err, lang), "error");
      }
    };
    if (cards.length === 0) {
      container.appendChild(
        el(
          "div",
          { class: "glass-card empty-state" },
          svgIcon("card", 40),
          el("h3", null, t(lang, "emptyCards")),
          el("p", null, t(lang, "emptyCardsSub"))
        )
      );
      return container;
    }
    const grid = el("div", { class: "cards-grid", "data-testid": "cards-grid" });
    for (const card of cards) {
      const d = card.data || {};
      const brand = detectCardBrand(d.number, d.brandOverride);
      const partial = Boolean(d.partial || isPartialCardNumber(d.number));
      const widget = build3DBankCardWidget({ data: d, lang, masked: true, isPreview: false });
      let reauthedCvv = false;
      const flipBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-sm",
          "aria-label": `${t(lang, "flipCard")} ${d.cardName}`,
          onClick: () => {
            triggerHaptic(10);
            widget.toggleFlip();
          }
        },
        svgIcon("flip", 15),
        t(lang, "flipCard")
      );
      const holdNumBtn = el(
        "button",
        { type: "button", class: "btn btn-sm", title: t(lang, "holdToReveal") },
        svgIcon("eye", 15),
        t(lang, "cardNumberLabel")
      );
      attachHoldToReveal(holdNumBtn, {
        onReveal: () => widget.setNumberText(formatCardNumber(d.number, brand)),
        onHide: () => widget.setNumberText(maskCardNumber(d.number, brand)),
        autoHideMs: 1e4
      });
      const revealCvvBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-sm",
          onClick: async () => {
            if (!reauthedCvv) {
              const ok = await requestReauth({ session: session2, lang });
              if (!ok) return;
              reauthedCvv = true;
            }
            widget.setFlipped(true);
            widget.setCvvText(d.cvv || "\u2014");
            widget.setPinText(d.pin || "\u2014");
            setTimeout(() => {
              widget.setCvvText("\u2022\u2022\u2022");
              widget.setPinText("\u2022\u2022\u2022\u2022");
              reauthedCvv = false;
            }, 1e4);
          }
        },
        svgIcon("eye", 15),
        "CVV / PIN"
      );
      const copyActions = el(
        "div",
        { class: "entry-actions-row" },
        d.number ? el("button", { type: "button", class: "btn btn-sm", onClick: () => copySecret(normalizeCardInput(d.number), t(lang, "cardNumberLabel")) }, svgIcon("copy", 14), t(lang, "cardNumberLabel")) : null,
        d.holderName ? el("button", { type: "button", class: "btn btn-sm", onClick: () => copySecret(d.holderName, t(lang, "holderNameLabel")) }, svgIcon("copy", 14), t(lang, "holderNameLabel")) : null,
        d.expiry ? el("button", { type: "button", class: "btn btn-sm", onClick: () => copySecret(d.expiry, t(lang, "expiryLabel")) }, svgIcon("copy", 14), d.expiry) : null,
        d.cvv ? el("button", {
          type: "button",
          class: "btn btn-sm",
          onClick: async () => {
            const ok = await requestReauth({ session: session2, lang });
            if (!ok) return;
            await copySecret(d.cvv, "CVV");
          }
        }, svgIcon("copy", 14), "CVV") : null,
        d.pin ? el("button", {
          type: "button",
          class: "btn btn-sm",
          onClick: async () => {
            const ok = await requestReauth({ session: session2, lang });
            if (!ok) return;
            await copySecret(d.pin, "PIN");
          }
        }, svgIcon("copy", 14), "PIN") : null,
        el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-primary",
            onClick: async () => {
              if (d.cvv || d.pin) {
                const ok = await requestReauth({ session: session2, lang });
                if (!ok) return;
              }
              await copySecret(formatCardCopyAll(d, lang), t(lang, "copyAll"));
            }
          },
          svgIcon("copy", 14),
          t(lang, "copyAll")
        )
      );
      const wrapper = el(
        "article",
        { class: "glass-card glass-card-compact bank-card-wrapper stagger-item" },
        widget.scene,
        partial ? el("div", { class: "banner banner-warn" }, el("span", null, t(lang, "partialCardBadge"))) : null,
        el(
          "div",
          { class: "entry-actions-row" },
          flipBtn,
          holdNumBtn,
          d.cvv || d.pin ? revealCvvBtn : null,
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": `${t(lang, "edit")} ${d.cardName}`,
              onClick: () => openCardEditorSheet({ session: session2, lang, card, onSaved: onRefresh })
            },
            svgIcon("edit", 14),
            t(lang, "edit")
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm btn-danger",
              "aria-label": `${t(lang, "delete")} ${d.cardName}`,
              onClick: async () => {
                await session2.trashRecord(card.id);
                showToast(t(lang, "delete"), "info");
                await onRefresh();
              }
            },
            svgIcon("trash", 14)
          )
        ),
        copyActions
      );
      grid.appendChild(wrapper);
    }
    container.appendChild(grid);
    return container;
  }
  function openCardEditorSheet({ session: session2, lang, card = null, onSaved }) {
    const init = card?.data || {
      cardName: "",
      bankName: "",
      holderName: "",
      number: "",
      expiry: "",
      cvv: "",
      pin: "",
      notes: "",
      theme: "aurora",
      brandOverride: "auto"
    };
    const state = { ...init };
    const preview = build3DBankCardWidget({ data: state, lang, masked: false, isPreview: true });
    const luhnBadge = el("div", { class: "settings-row-desc" }, "");
    const syncLive = () => {
      preview.updateLive(state);
      const num = normalizeCardInput(state.number);
      if (!num) {
        luhnBadge.textContent = "";
      } else if (isPartialCardNumber(num)) {
        luhnBadge.textContent = t(lang, "partialCardBadge");
      } else if (num.length >= 13) {
        const ok = validateLuhn(num);
        luhnBadge.textContent = ok ? t(lang, "luhnValid") : t(lang, "luhnInvalid");
      } else {
        luhnBadge.textContent = "";
      }
    };
    const nameIn = el("input", {
      id: "ce-name",
      type: "text",
      class: "input",
      value: state.cardName,
      required: true,
      autocomplete: "off",
      placeholder: lang === "en" ? "e.g. Salary Card" : "\u0645\u062B\u0627\u0644: \u0628\u0637\u0627\u0642\u0629 \u0627\u0644\u0631\u0627\u062A\u0628",
      onInput: (e) => {
        state.cardName = e.target.value;
        syncLive();
      }
    });
    const bankIn = el("input", {
      id: "ce-bank",
      type: "text",
      class: "input",
      value: state.bankName,
      autocomplete: "off",
      onInput: (e) => {
        state.bankName = e.target.value;
        syncLive();
      }
    });
    const holderIn = el("input", {
      id: "ce-holder",
      type: "text",
      class: "input ltr-value",
      value: state.holderName,
      autocomplete: "off",
      spellcheck: "false",
      onInput: (e) => {
        state.holderName = e.target.value;
        syncLive();
      }
    });
    const numIn = el("input", {
      id: "ce-num",
      type: "text",
      inputmode: "numeric",
      class: "input ltr-value",
      value: formatCardNumber(state.number, detectCardBrand(state.number, state.brandOverride)),
      autocomplete: "off",
      spellcheck: "false",
      placeholder: "4532 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022",
      onFocus: () => preview.setFlipped(false),
      onInput: (e) => {
        state.number = normalizeCardInput(e.target.value).slice(0, 19);
        syncLive();
      }
    });
    const expIn = el("input", {
      id: "ce-exp",
      type: "text",
      inputmode: "numeric",
      class: "input ltr-value",
      value: state.expiry,
      maxlength: 5,
      autocomplete: "off",
      placeholder: "MM/YY",
      onFocus: () => preview.setFlipped(false),
      onInput: (e) => {
        const f = formatExpiry(e.target.value);
        e.target.value = f;
        state.expiry = f;
        syncLive();
      }
    });
    const cvvIn = el("input", {
      id: "ce-cvv",
      type: "password",
      inputmode: "numeric",
      class: "input ltr-value",
      value: state.cvv,
      maxlength: 4,
      autocomplete: "off",
      spellcheck: "false",
      onFocus: () => preview.setFlipped(true),
      onInput: (e) => {
        state.cvv = e.target.value.replace(/\D+/g, "").slice(0, 4);
        syncLive();
      }
    });
    const pinIn = el("input", {
      id: "ce-pin",
      type: "password",
      inputmode: "numeric",
      class: "input ltr-value",
      value: state.pin,
      maxlength: 8,
      autocomplete: "off",
      spellcheck: "false",
      onFocus: () => preview.setFlipped(true),
      onInput: (e) => {
        state.pin = e.target.value.replace(/\D+/g, "").slice(0, 8);
        syncLive();
      }
    });
    const brandSel = el(
      "select",
      {
        id: "ce-brand",
        class: "select",
        onChange: (e) => {
          state.brandOverride = e.target.value;
          syncLive();
        }
      },
      ...CARD_BRANDS.map((b) => el("option", { value: b.id, selected: state.brandOverride === b.id }, lang === "en" ? b.labelEn : b.labelAr))
    );
    const themeSel = el(
      "select",
      {
        id: "ce-theme",
        class: "select",
        onChange: (e) => {
          state.theme = e.target.value;
          syncLive();
        }
      },
      ...CARD_THEMES.map((th) => el("option", { value: th.id, selected: state.theme === th.id }, lang === "en" ? th.labelEn : th.labelAr))
    );
    const notesIn = el("textarea", { id: "ce-notes", class: "textarea", autocomplete: "off" }, state.notes);
    syncLive();
    const form = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          if (!state.cardName.trim()) return;
          await session2.saveRecord({
            id: card?.id || null,
            type: "card",
            createdAt: card?.createdAt,
            data: {
              ...state,
              cardName: state.cardName.trim(),
              bankName: state.bankName.trim(),
              holderName: state.holderName.trim(),
              number: normalizeCardInput(state.number),
              notes: notesIn.value,
              partial: isPartialCardNumber(state.number)
            }
          });
          sheet.close();
          showToast(t(lang, "save"), "success");
          onSaved && await onSaved();
        }
      },
      el(
        "div",
        { class: "settings-group" },
        preview.scene,
        el(
          "button",
          { type: "button", class: "btn btn-sm", onClick: () => preview.toggleFlip() },
          svgIcon("flip", 15),
          t(lang, "flipCard")
        )
      ),
      el("div", { class: "field" }),
      el(
        "div",
        { class: "form-grid-2" },
        el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-name" }, t(lang, "cardNameLabel")), nameIn),
        el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-bank" }, t(lang, "bankNameLabel")), bankIn)
      ),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-holder" }, t(lang, "holderNameLabel")), holderIn),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-num" }, t(lang, "cardNumberLabel")), numIn, luhnBadge),
      el(
        "div",
        { class: "form-grid-2" },
        el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-exp" }, t(lang, "expiryLabel")), expIn),
        el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-cvv" }, t(lang, "cvvLabel")), cvvIn)
      ),
      el(
        "div",
        { class: "form-grid-2" },
        el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-pin" }, t(lang, "pinLabel")), pinIn),
        el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-brand" }, t(lang, "cardBrandLabel")), brandSel)
      ),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-theme" }, t(lang, "cardThemeLabel")), themeSel),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "ce-notes" }, t(lang, "notesLabel")), notesIn),
      el(
        "div",
        { class: "form-grid-2" },
        el("button", { type: "button", class: "btn", onClick: () => sheet.close() }, t(lang, "cancel")),
        el("button", { type: "submit", class: "btn btn-primary" }, t(lang, "save"))
      )
    );
    const sheet = openBottomSheet({
      title: card ? t(lang, "editCard") : t(lang, "addCard"),
      content: form
    });
  }

  // src/import-export/csv.js
  var CSV_TARGET_FIELDS = Object.freeze([
    "ignore",
    "title",
    "url",
    "username",
    "password",
    "notes",
    "folder",
    "favorite"
  ]);
  function detectCsvDelimiter(rawText) {
    const text = String(rawText || "").replace(/^\uFEFF/, "");
    const firstLineEnd = text.search(/\r?\n/);
    const sample = firstLineEnd === -1 ? text.slice(0, 2e3) : text.slice(0, firstLineEnd);
    const candidates = [",", ";", "	"];
    let bestDelim = ",";
    let bestScore = -1;
    for (const delim of candidates) {
      let inQuotes = false;
      let count = 0;
      for (let i = 0; i < sample.length; i++) {
        const ch = sample[i];
        if (ch === '"') {
          if (inQuotes && sample[i + 1] === '"') {
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (!inQuotes && ch === delim) {
          count++;
        }
      }
      if (count > bestScore) {
        bestScore = count;
        bestDelim = delim;
      }
    }
    return bestScore > 0 ? bestDelim : ",";
  }
  function parseCsv(rawText, explicitDelimiter = null) {
    const text = String(rawText || "").replace(/^\uFEFF/, "");
    if (!text.trim()) {
      return { headers: [], rows: [], delimiter: explicitDelimiter || "," };
    }
    const delimiter = explicitDelimiter || detectCsvDelimiter(text);
    const rows = [];
    let row = [];
    let field = "";
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inQuotes) {
        if (ch === '"') {
          if (text[i + 1] === '"') {
            field += '"';
            i++;
          } else {
            inQuotes = false;
          }
        } else {
          field += ch;
        }
      } else if (ch === '"' && field.length === 0) {
        inQuotes = true;
      } else if (ch === delimiter) {
        row.push(field);
        field = "";
      } else if (ch === "\r") {
        if (text[i + 1] === "\n") i++;
        row.push(field);
        rows.push(row);
        row = [];
        field = "";
      } else if (ch === "\n") {
        row.push(field);
        rows.push(row);
        row = [];
        field = "";
      } else {
        field += ch;
      }
    }
    if (field.length > 0 || row.length > 0) {
      row.push(field);
      rows.push(row);
    }
    const nonEmpty = rows.filter((r) => r.some((cell) => cell.trim() !== ""));
    if (nonEmpty.length === 0) {
      return { headers: [], rows: [], delimiter };
    }
    const headers = nonEmpty[0].map((h) => h.trim());
    const dataRows = nonEmpty.slice(1);
    return { headers, rows: dataRows, delimiter };
  }
  function serializeCsv(headers, rows, delimiter = ",") {
    const escapeCell = (val) => {
      const s = String(val ?? "");
      if (s.includes('"') || s.includes(delimiter) || s.includes("\n") || s.includes("\r")) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };
    const lines = [headers.map(escapeCell).join(delimiter)];
    for (const r of rows) {
      lines.push(r.map(escapeCell).join(delimiter));
    }
    return lines.join("\n");
  }
  var SYNONYMS = Object.freeze({
    title: ["name", "title", "account", "service", "site", "website name", "label", "\u0627\u0633\u0645", "\u0627\u0644\u0639\u0646\u0648\u0627\u0646", "\u0627\u0644\u0627\u0633\u0645"],
    url: ["url", "uri", "login_uri", "website", "web site", "homepage", "origin", "domain", "\u0627\u0644\u0645\u0648\u0642\u0639", "\u0627\u0644\u0631\u0627\u0628\u0637"],
    username: ["username", "login_username", "user", "login", "email", "e-mail", "user name", "userid", "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645", "\u0627\u0644\u0628\u0631\u064A\u062F"],
    password: ["password", "login_password", "pass", "pwd", "secret", "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631", "\u0627\u0644\u0631\u0645\u0632"],
    notes: ["note", "notes", "extra", "comment", "comments", "memo", "description", "\u0645\u0644\u0627\u062D\u0638\u0627\u062A", "\u0645\u0644\u0627\u062D\u0638\u0629"],
    folder: ["folder", "grouping", "group", "category", "collection", "section", "\u0627\u0644\u0642\u0633\u0645", "\u0627\u0644\u0645\u062C\u0644\u062F"],
    favorite: ["fav", "favorite", "favourite", "starred", "\u0645\u0641\u0636\u0644\u0629"]
  });
  function detectCsvPresetAndMapping(headers) {
    const lower = headers.map((h) => h.toLowerCase().trim());
    const has = (...cols) => cols.every((c) => lower.includes(c));
    let preset = "generic-csv";
    if (has("login_username", "login_password")) preset = "bitwarden-csv";
    else if (has("grouping", "extra", "fav")) preset = "lastpass-csv";
    else if (has("httprealm", "formactionorigin")) preset = "firefox-csv";
    else if (has("otpauth", "title", "url", "username", "password")) preset = "apple-csv";
    else if (has("group", "title", "username", "password", "url")) preset = "keepass-csv";
    else if (has("username2", "username3") || has("title", "url", "username", "password", "note") && lower.includes("category")) {
      preset = "dashlane-csv";
    } else if (has("title", "website", "username", "password")) preset = "1password-csv";
    else if (has("name", "url", "username", "password")) preset = "chrome-csv";
    const columnMap = {};
    const assigned = /* @__PURE__ */ new Set();
    for (let i = 0; i < lower.length; i++) {
      const h = lower[i];
      let matched = "ignore";
      for (const [target, keys] of Object.entries(SYNONYMS)) {
        if (!assigned.has(target) && keys.includes(h)) {
          matched = target;
          assigned.add(target);
          break;
        }
      }
      columnMap[i] = matched;
    }
    return { preset, columnMap };
  }
  function mapCsvRowsToEntries({ headers, rows, columnMap }) {
    const passwords = [];
    const errors = [];
    for (let rIdx = 0; rIdx < rows.length; rIdx++) {
      const row = rows[rIdx];
      const item = {
        title: "",
        url: "",
        username: "",
        password: "",
        notes: "",
        folder: "",
        favorite: false
      };
      for (let cIdx = 0; cIdx < headers.length; cIdx++) {
        const target = columnMap[cIdx];
        if (!target || target === "ignore") continue;
        const val = row[cIdx] ?? "";
        if (target === "favorite") {
          item.favorite = /^(1|true|yes|y)$/i.test(val.trim());
        } else if (target === "notes") {
          item.notes = item.notes ? `${item.notes}
${val}` : val;
        } else if (!item[target]) {
          item[target] = val.trim();
        }
      }
      if (!item.title && item.url) {
        try {
          const u = new URL(/^[a-z]+:\/\//i.test(item.url) ? item.url : `https://${item.url}`);
          item.title = u.hostname.replace(/^www\./i, "");
        } catch {
          item.title = item.url;
        }
      }
      if (!item.title && !item.username && !item.password && !item.url) {
        continue;
      }
      if (!item.title) {
        item.title = item.username || `Row ${rIdx + 2}`;
      }
      passwords.push(item);
    }
    return { passwords, errors };
  }

  // src/import-export/spass.js
  var SPASS_PBKDF2_ITERATIONS = 7e4;
  var SPASS_SALT_LEN = 20;
  var SPASS_IV_LEN = 16;
  var BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
  function decodeSpassField(raw, forceBase64 = false) {
    const s = String(raw ?? "").trim();
    if (!s || s === "&&&NULL&&&" || s === "null" || s === "NULL") return "";
    if (forceBase64 || s.length >= 4 && s.length % 4 === 0 && BASE64_PATTERN.test(s)) {
      if (!forceBase64 && (/^[a-zA-Z]{4,8}$/.test(s) || /^\d{4,16}$/.test(s))) {
        return s;
      }
      try {
        const bytes = base64ToBytes(s);
        const decoded = utf8Decode(bytes);
        if (!/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(decoded)) {
          if (decoded === "&&&NULL&&&") return "";
          return decoded;
        }
      } catch {
      }
    }
    return s;
  }
  function encodeSpassField(val) {
    const s = String(val ?? "");
    if (!s) return "&&&NULL&&&";
    return bytesToBase64(utf8Encode(s));
  }
  async function decryptSpass(rawBase64Text, password) {
    if (!password) {
      throw new KhaznaError(
        "SPASS_PASSWORD_REQUIRED",
        "\u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u062A\u064A \u0627\u062E\u062A\u0631\u062A\u0647\u0627 \u0639\u0646\u062F \u062A\u0635\u062F\u064A\u0631 \u0645\u0644\u0641 Samsung Pass (.spass).",
        "Enter the export password used when creating the Samsung Pass (.spass) file."
      );
    }
    let rawBytes;
    try {
      rawBytes = base64ToBytes(rawBase64Text);
    } catch (err) {
      throw new KhaznaError(
        "SPASS_INVALID_FORMAT",
        "\u0645\u0644\u0641 .spass \u063A\u064A\u0631 \u0635\u0627\u0644\u062D (\u0641\u0634\u0644 \u0641\u0643 \u062A\u0631\u0645\u064A\u0632 Base64 \u0627\u0644\u062E\u0627\u0631\u062C\u064A).",
        "Invalid .spass file (outer Base64 decoding failed).",
        err
      );
    }
    if (rawBytes.length < SPASS_SALT_LEN + SPASS_IV_LEN + 16) {
      throw new KhaznaError(
        "SPASS_TOO_SHORT",
        "\u0645\u0644\u0641 .spass \u0646\u0627\u0642\u0635 \u0623\u0648 \u062A\u0627\u0644\u0641 (\u062D\u062C\u0645\u0647 \u0623\u0635\u063A\u0631 \u0645\u0646 \u0627\u0644\u062D\u062F \u0627\u0644\u0623\u062F\u0646\u0649 \u0627\u0644\u0645\u0637\u0644\u0648\u0628).",
        ".spass file is truncated or corrupted."
      );
    }
    const salt = rawBytes.subarray(0, SPASS_SALT_LEN);
    const iv = rawBytes.subarray(SPASS_SALT_LEN, SPASS_SALT_LEN + SPASS_IV_LEN);
    const ciphertext = rawBytes.subarray(SPASS_SALT_LEN + SPASS_IV_LEN);
    if (ciphertext.length % 16 !== 0) {
      throw new KhaznaError(
        "SPASS_BAD_BLOCK_LEN",
        "\u0645\u0644\u0641 .spass \u062A\u0627\u0644\u0641 (\u0637\u0648\u0644 \u0627\u0644\u0646\u0635 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 \u063A\u064A\u0631 \u0645\u062A\u0648\u0627\u0641\u0642 \u0645\u0639 AES-CBC).",
        ".spass ciphertext length is not a multiple of AES block size."
      );
    }
    const pwdBytes = utf8Encode(password);
    let keyBytes = null;
    let plainBytes = null;
    try {
      keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, SPASS_PBKDF2_ITERATIONS, 32);
      const aesKey = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-CBC", length: 256 },
        false,
        ["decrypt"]
      );
      const decrypted = await globalThis.crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        aesKey,
        ciphertext
      );
      plainBytes = new Uint8Array(decrypted);
      const text = utf8Decode(plainBytes);
      if (!text.includes(";") && !text.includes("next_table")) {
        throw new KhaznaError(
          "SPASS_UNEXPECTED_CONTENT",
          "\u062A\u0645 \u0641\u0643 \u0627\u0644\u062A\u0634\u0641\u064A\u0631 \u0644\u0643\u0646 \u0628\u0646\u064A\u0629 \u0645\u0644\u0641 .spass \u063A\u064A\u0631 \u0645\u062A\u0648\u0642\u0639\u0629. \u062A\u0623\u0643\u062F \u0645\u0646 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0648\u0625\u0635\u062F\u0627\u0631 Samsung Pass.",
          "Decrypted .spass content has unexpected structure. Verify password and export version."
        );
      }
      return text;
    } catch (err) {
      if (err instanceof KhaznaError) throw err;
      throw new KhaznaError(
        "SPASS_DECRYPT_FAILED",
        "\u0641\u0634\u0644 \u0641\u0643 \u062A\u0634\u0641\u064A\u0631 \u0645\u0644\u0641 .spass \u2014 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629 \u0623\u0648 \u0627\u0644\u0645\u0644\u0641 \u062A\u0627\u0644\u0641.",
        "Failed to decrypt .spass file \u2014 wrong export password or corrupted file.",
        err
      );
    } finally {
      zeroize(pwdBytes, keyBytes, plainBytes);
    }
  }
  function parseSpassPlaintext(plaintext) {
    const lines = String(plaintext || "").replace(/^\uFEFF/, "").split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
    if (lines.length < 2) {
      throw new KhaznaError(
        "SPASS_EMPTY",
        "\u0645\u0644\u0641 Samsung Pass \u0641\u0627\u0631\u063A \u0623\u0648 \u0644\u0627 \u064A\u062D\u062A\u0648\u064A \u0639\u0644\u0649 \u062C\u062F\u0627\u0648\u0644 \u0628\u064A\u0627\u0646\u0627\u062A.",
        "Samsung Pass plaintext contains no data tables."
      );
    }
    let cursor = 0;
    let formatVersion = lines[0];
    const tables = [];
    while (cursor < lines.length) {
      if (lines[cursor].toLowerCase() === "next_table") {
        cursor++;
        const tableLines = [];
        while (cursor < lines.length && lines[cursor].toLowerCase() !== "next_table") {
          tableLines.push(lines[cursor]);
          cursor++;
        }
        if (tableLines.length > 0) tables.push(tableLines);
      } else {
        cursor++;
      }
    }
    if (tables.length === 0) {
      const headerIdx = lines.findIndex((l) => l.includes(";") && /url|username|password|card|note/i.test(l));
      if (headerIdx !== -1) {
        tables.push(lines.slice(headerIdx));
      }
    }
    const passwords = [];
    const cards = [];
    const notes = [];
    const warnings = [];
    for (const table of tables) {
      const headerCols = table[0].split(";").map((c) => c.trim().toLowerCase());
      const dataLines = table.slice(1);
      if (dataLines.length === 0) continue;
      const colIdx = (...names) => {
        for (const n of names) {
          const i = headerCols.indexOf(n);
          if (i !== -1) return i;
        }
        return -1;
      };
      const isPasswordTable = colIdx("password_value", "password") !== -1 && colIdx("origin_url", "action_url", "host_url", "url", "username_value", "username") !== -1;
      const isCardTable = colIdx("card_number", "card_number_encrypted", "name_on_card", "expiration_month", "card_holder") !== -1;
      const isNoteTable = colIdx("note_title", "note_detail", "note_content", "title", "body") !== -1 && !isPasswordTable && !isCardTable;
      if (isPasswordTable) {
        const iTitle = colIdx("credential_memo", "title", "name", "app_name", "host_url");
        const iUrl = colIdx("origin_url", "action_url", "host_url", "url");
        const iUser = colIdx("username_value", "username", "id");
        const iPass = colIdx("password_value", "password");
        const iNote = colIdx("credential_memo", "note", "memo", "extra");
        const iName = colIdx("title", "name", "app_name", "package_name");
        for (const line of dataLines) {
          const cols = line.split(";");
          const url = iUrl !== -1 ? decodeSpassField(cols[iUrl]) : "";
          const username = iUser !== -1 ? decodeSpassField(cols[iUser]) : "";
          const password = iPass !== -1 ? decodeSpassField(cols[iPass]) : "";
          const rawTitle = iName !== -1 ? decodeSpassField(cols[iName]) : iTitle !== -1 ? decodeSpassField(cols[iTitle]) : "";
          const memo = iNote !== -1 && iNote !== iName ? decodeSpassField(cols[iNote]) : "";
          if (!url && !username && !password && !rawTitle) continue;
          let title = rawTitle;
          if (!title && url) {
            try {
              title = new URL(/^[a-z]+:\/\//i.test(url) ? url : `https://${url}`).hostname.replace(/^www\./i, "");
            } catch {
              title = url;
            }
          }
          passwords.push({
            title: title || username || "Samsung Pass",
            url,
            username,
            password,
            notes: memo,
            folder: "Samsung Pass",
            favorite: false
          });
        }
      } else if (isCardTable) {
        const iLabel = colIdx("card_nickname", "card_name", "title", "label");
        const iBank = colIdx("bank_name", "issuer", "bank");
        const iHolder = colIdx("name_on_card", "card_holder", "holder_name");
        const iNum = colIdx("card_number", "card_number_encrypted", "number");
        const iFirst6 = colIdx("card_first_six", "first_six", "bin");
        const iLast4 = colIdx("card_last_four", "last_four");
        const iMonth = colIdx("expiration_month", "exp_month", "month");
        const iYear = colIdx("expiration_year", "exp_year", "year");
        const iExpiry = colIdx("expiration_date", "expiry");
        const iCvv = colIdx("cvv", "security_code", "card_cvv");
        const iNote = colIdx("memo", "note", "notes");
        for (const line of dataLines) {
          const cols = line.split(";");
          const cardName = iLabel !== -1 ? decodeSpassField(cols[iLabel]) : "";
          const bankName = iBank !== -1 ? decodeSpassField(cols[iBank]) : "";
          const holderName = iHolder !== -1 ? decodeSpassField(cols[iHolder]) : "";
          let number = iNum !== -1 ? decodeSpassField(cols[iNum]) : "";
          if (!number && (iFirst6 !== -1 || iLast4 !== -1)) {
            const f6 = iFirst6 !== -1 ? decodeSpassField(cols[iFirst6]) : "";
            const l4 = iLast4 !== -1 ? decodeSpassField(cols[iLast4]) : "";
            if (f6 || l4) {
              number = `${f6 || "******"}******${l4 || "****"}`;
            }
          }
          number = number.replace(/[\s\-]+/g, "").replace(/[xX•]/g, "*");
          let expiry = iExpiry !== -1 ? decodeSpassField(cols[iExpiry]) : "";
          if (!expiry && (iMonth !== -1 || iYear !== -1)) {
            const mm = (iMonth !== -1 ? decodeSpassField(cols[iMonth]) : "").padStart(2, "0");
            const yyRaw = iYear !== -1 ? decodeSpassField(cols[iYear]) : "";
            const yy = yyRaw.length === 4 ? yyRaw.slice(2) : yyRaw.padStart(2, "0");
            if (mm !== "00" && yy !== "00") expiry = `${mm}/${yy}`;
          }
          const cvv = iCvv !== -1 ? decodeSpassField(cols[iCvv]) : "";
          const notesText = iNote !== -1 ? decodeSpassField(cols[iNote]) : "";
          if (!cardName && !holderName && !number) continue;
          const isPartial = number.includes("*") || number.length < 13;
          cards.push({
            cardName: cardName || bankName || "\u0628\u0637\u0627\u0642\u0629 Samsung Pass",
            bankName,
            holderName,
            number,
            expiry,
            cvv,
            pin: "",
            notes: notesText,
            theme: "aurora",
            brandOverride: "auto",
            partial: isPartial
          });
        }
      } else if (isNoteTable) {
        const iTitle = colIdx("note_title", "title", "name");
        const iBody = colIdx("note_detail", "note_content", "body", "content", "note");
        for (const line of dataLines) {
          const cols = line.split(";");
          const title = iTitle !== -1 ? decodeSpassField(cols[iTitle]) : "";
          const body = iBody !== -1 ? decodeSpassField(cols[iBody]) : "";
          if (!title && !body) continue;
          notes.push({
            title: title || "\u0645\u0644\u0627\u062D\u0638\u0629 Samsung Pass",
            body,
            checklist: [],
            pinned: false
          });
        }
      } else {
        warnings.push(`Skipped unrecognized Samsung Pass table (${headerCols.slice(0, 3).join(", ")})`);
      }
    }
    return {
      formatVersion,
      passwords,
      cards,
      notes,
      warnings
    };
  }
  async function importSpass(rawBase64Text, password) {
    const plaintext = await decryptSpass(rawBase64Text, password);
    return parseSpassPlaintext(plaintext);
  }
  async function exportSpass({ passwords = [], cards = [], notes = [] }, exportPassword) {
    if (!exportPassword || exportPassword.length < 4) {
      throw new KhaznaError(
        "SPASS_EXPORT_PASSWORD_REQUIRED",
        "\u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0644\u062A\u0634\u0641\u064A\u0631 \u0645\u0644\u0641 .spass (\u0664 \u0623\u062D\u0631\u0641 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644).",
        "Enter an export password (at least 4 characters) for .spass export."
      );
    }
    const lines = [];
    lines.push("28");
    lines.push(`${passwords.length > 0};${cards.length > 0};false;${notes.length > 0}`);
    lines.push("next_table");
    lines.push("id;origin_url;action_url;username_element;username_value;password_element;password_value;host_url;title;credential_memo");
    passwords.forEach((p, idx) => {
      lines.push([
        String(idx + 1),
        encodeSpassField(p.url || ""),
        encodeSpassField(p.url || ""),
        "&&&NULL&&&",
        encodeSpassField(p.username || ""),
        "&&&NULL&&&",
        encodeSpassField(p.password || ""),
        encodeSpassField(p.url || ""),
        encodeSpassField(p.title || ""),
        encodeSpassField(p.notes || "")
      ].join(";"));
    });
    lines.push("next_table");
    lines.push("id;card_nickname;bank_name;name_on_card;card_number;expiration_month;expiration_year;cvv;memo");
    cards.forEach((c, idx) => {
      const [mm = "", yy = ""] = String(c.expiry || "").split("/");
      lines.push([
        String(idx + 1),
        encodeSpassField(c.cardName || ""),
        encodeSpassField(c.bankName || ""),
        encodeSpassField(c.holderName || ""),
        encodeSpassField(c.number || ""),
        encodeSpassField(mm),
        encodeSpassField(yy ? yy.length === 2 ? `20${yy}` : yy : ""),
        encodeSpassField(c.cvv || ""),
        encodeSpassField(c.notes || "")
      ].join(";"));
    });
    lines.push("next_table");
    lines.push("id;note_title;note_detail");
    notes.forEach((n, idx) => {
      const bodyWithChecklist = n.checklist?.length ? `${n.body || ""}
${n.checklist.map((i) => `${i.done ? "[x]" : "[ ]"} ${i.text}`).join("\n")}`.trim() : n.body || "";
      lines.push([
        String(idx + 1),
        encodeSpassField(n.title || ""),
        encodeSpassField(bodyWithChecklist)
      ].join(";"));
    });
    const plaintextBytes = utf8Encode(lines.join("\n"));
    const salt = randomBytes(SPASS_SALT_LEN);
    const iv = randomBytes(SPASS_IV_LEN);
    const pwdBytes = utf8Encode(exportPassword);
    let keyBytes = null;
    try {
      keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, SPASS_PBKDF2_ITERATIONS, 32);
      const aesKey = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-CBC", length: 256 },
        false,
        ["encrypt"]
      );
      const ctBuf = await globalThis.crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        aesKey,
        plaintextBytes
      );
      const combined = concatBytes(salt, iv, new Uint8Array(ctBuf));
      return bytesToBase64(combined);
    } finally {
      zeroize(plaintextBytes, pwdBytes, keyBytes);
    }
  }

  // src/import-export/formats.js
  function detectImportFormat(rawText, fileName = "") {
    const nameLower = String(fileName || "").toLowerCase();
    const trimmed = String(rawText || "").replace(/^\uFEFF/, "").trim();
    if (!trimmed) {
      throw new KhaznaError("EMPTY_IMPORT", "\u0627\u0644\u0645\u0644\u0641 \u0623\u0648 \u0627\u0644\u0646\u0635 \u0627\u0644\u0645\u064F\u062F\u062E\u0644 \u0641\u0627\u0631\u063A.", "Import content is empty.");
    }
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && !Array.isArray(parsed) && parsed.format === BACKUP_FORMAT_ID) {
          return { format: "khazna-vault", requiresPassword: true };
        }
        if (parsed && !Array.isArray(parsed) && parsed.format === "khazna-plain-json") {
          return { format: "khazna-json", requiresPassword: false };
        }
        if (parsed && !Array.isArray(parsed) && Array.isArray(parsed.items)) {
          return { format: "bitwarden-json", requiresPassword: false };
        }
        return { format: "generic-json", requiresPassword: false };
      } catch {
      }
    }
    if (nameLower.endsWith(".spass") || !trimmed.includes(",") && !trimmed.includes(";") && !trimmed.includes("	") && /^[A-Za-z0-9+/=\r\n]{64,}$/.test(trimmed)) {
      return { format: "spass", requiresPassword: true };
    }
    const { headers } = parseCsv(trimmed);
    if (headers.length >= 2) {
      const { preset } = detectCsvPresetAndMapping(headers);
      return { format: preset, isCsv: true, requiresPassword: false };
    }
    throw new KhaznaError(
      "UNRECOGNIZED_FORMAT",
      "\u062A\u0639\u0630\u0651\u0631 \u0627\u0644\u062A\u0639\u0631\u0651\u0641 \u0639\u0644\u0649 \u0635\u064A\u063A\u0629 \u0627\u0644\u0645\u0644\u0641. \u0627\u0644\u0635\u064A\u063A \u0627\u0644\u0645\u062F\u0639\u0648\u0645\u0629: .vault \u0648 .spass \u0648 JSON \u0648 CSV.",
      "Unrecognized import format. Supported: .vault, .spass, JSON, CSV."
    );
  }
  function pickSynonym(obj, keys) {
    if (!obj || typeof obj !== "object") return "";
    const map = new Map(Object.entries(obj).map(([k, v]) => [k.toLowerCase().trim(), v]));
    for (const key of keys) {
      const val = map.get(key.toLowerCase());
      if (val !== void 0 && val !== null && val !== "") return String(val);
    }
    return "";
  }
  function parseBitwardenJson(parsed) {
    const folderMap = /* @__PURE__ */ new Map();
    const sections = [];
    for (const f of parsed.folders || []) {
      if (f?.id && f?.name) {
        folderMap.set(f.id, f.name);
        sections.push({ name: f.name, emoji: "\u{1F4C1}", color: "#38bdf8" });
      }
    }
    const passwords = [];
    const cards = [];
    const notes = [];
    for (const item of parsed.items || []) {
      const folder = item.folderId ? folderMap.get(item.folderId) || "" : "";
      const fav = Boolean(item.favorite);
      if (item.type === 1 || item.login) {
        const login = item.login || {};
        const firstUri = Array.isArray(login.uris) && login.uris[0]?.uri ? login.uris[0].uri : "";
        passwords.push({
          title: item.name || firstUri || "Login",
          url: firstUri,
          username: login.username || "",
          password: login.password || "",
          notes: item.notes || "",
          folder,
          favorite: fav
        });
      } else if (item.type === 3 || item.card) {
        const c = item.card || {};
        const mm = String(c.expMonth || "").padStart(2, "0");
        const yyRaw = String(c.expYear || "");
        const yy = yyRaw.length === 4 ? yyRaw.slice(2) : yyRaw.padStart(2, "0");
        const expiry = mm !== "00" && yy !== "00" ? `${mm}/${yy}` : "";
        cards.push({
          cardName: item.name || c.brand || "Card",
          bankName: "",
          holderName: c.cardholderName || "",
          number: String(c.number || "").replace(/[\s\-]+/g, ""),
          expiry,
          cvv: String(c.code || ""),
          pin: "",
          notes: item.notes || "",
          theme: "obsidian",
          brandOverride: "auto"
        });
      } else if (item.type === 2) {
        notes.push({
          title: item.name || "Note",
          body: item.notes || "",
          checklist: [],
          pinned: fav
        });
      }
    }
    return { sections, passwords, cards, notes, warnings: [] };
  }
  function parseGenericJson(parsed) {
    let list = [];
    if (Array.isArray(parsed)) {
      list = parsed;
    } else if (parsed && typeof parsed === "object") {
      list = parsed.passwords || parsed.logins || parsed.entries || parsed.accounts || parsed.data || [];
      if (!Array.isArray(list)) list = [parsed];
    }
    const passwords = [];
    const cards = Array.isArray(parsed?.cards) ? parsed.cards : [];
    const notes = Array.isArray(parsed?.notes) ? parsed.notes : [];
    const sections = Array.isArray(parsed?.sections) ? parsed.sections : [];
    for (const row of list) {
      if (!row || typeof row !== "object") continue;
      const title = pickSynonym(row, ["name", "title", "service", "site", "account", "label", "\u0627\u0644\u0627\u0633\u0645", "\u0627\u0644\u0639\u0646\u0648\u0627\u0646"]);
      const url = pickSynonym(row, ["url", "uri", "website", "link", "origin", "domain", "\u0627\u0644\u0645\u0648\u0642\u0639"]);
      const username = pickSynonym(row, ["username", "login", "email", "user", "userid", "\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645"]);
      const password = pickSynonym(row, ["password", "pass", "pwd", "secret", "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631"]);
      const note = pickSynonym(row, ["note", "notes", "memo", "extra", "comment", "description", "\u0645\u0644\u0627\u062D\u0638\u0627\u062A"]);
      const folder = pickSynonym(row, ["folder", "group", "category", "section", "\u0627\u0644\u0642\u0633\u0645", "\u0627\u0644\u0645\u062C\u0644\u062F"]);
      if (!title && !url && !username && !password) continue;
      passwords.push({
        title: title || url || username || "Entry",
        url,
        username,
        password,
        notes: note,
        folder,
        favorite: Boolean(row.favorite || row.fav || row.starred)
      });
    }
    return { sections, passwords, cards, notes, warnings: [] };
  }
  async function parseImportSource({
    rawText,
    fileName = "",
    password = "",
    customCsvMapping = null,
    useWorker = true
  }) {
    const detected = detectImportFormat(rawText, fileName);
    if (detected.format === "khazna-vault") {
      if (!password) {
        throw new KhaznaError(
          "VAULT_PASSWORD_REQUIRED",
          "\u0623\u062F\u062E\u0644 \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0645\u0644\u0641 \u0627\u0644\u0646\u0633\u062E\u0629 \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 (.vault).",
          "Enter the password for this encrypted .vault backup."
        );
      }
      const { payload } = await decryptVaultBackup(rawText, password, { useWorker });
      return {
        format: "khazna-vault",
        sections: Array.isArray(payload.sections) ? payload.sections : [],
        passwords: Array.isArray(payload.passwords) ? payload.passwords : [],
        cards: Array.isArray(payload.cards) ? payload.cards : [],
        notes: Array.isArray(payload.notes) ? payload.notes : [],
        warnings: []
      };
    }
    if (detected.format === "spass") {
      const res = await importSpass(rawText, password);
      return {
        format: "spass",
        sections: [{ name: "Samsung Pass", emoji: "\u{1F4F1}", color: "#38bdf8" }],
        passwords: res.passwords,
        cards: res.cards,
        notes: res.notes,
        warnings: res.warnings
      };
    }
    if (detected.format === "khazna-json") {
      const parsed = JSON.parse(rawText.replace(/^\uFEFF/, ""));
      return {
        format: "khazna-json",
        sections: Array.isArray(parsed.sections) ? parsed.sections : [],
        passwords: Array.isArray(parsed.passwords) ? parsed.passwords : [],
        cards: Array.isArray(parsed.cards) ? parsed.cards : [],
        notes: Array.isArray(parsed.notes) ? parsed.notes : [],
        warnings: []
      };
    }
    if (detected.format === "bitwarden-json") {
      const parsed = JSON.parse(rawText.replace(/^\uFEFF/, ""));
      return {
        format: "bitwarden-json",
        ...parseBitwardenJson(parsed)
      };
    }
    if (detected.format === "generic-json") {
      const parsed = JSON.parse(rawText.replace(/^\uFEFF/, ""));
      return {
        format: "generic-json",
        ...parseGenericJson(parsed)
      };
    }
    const parsedCsv = parseCsv(rawText);
    const { preset, columnMap } = detectCsvPresetAndMapping(parsedCsv.headers);
    const activeMap = customCsvMapping || columnMap;
    const mapped = mapCsvRowsToEntries({
      headers: parsedCsv.headers,
      rows: parsedCsv.rows,
      columnMap: activeMap
    });
    return {
      format: preset,
      isCsv: true,
      csvHeaders: parsedCsv.headers,
      csvColumnMap: activeMap,
      csvRowCount: parsedCsv.rows.length,
      sections: [],
      passwords: mapped.passwords,
      cards: [],
      notes: [],
      warnings: mapped.errors
    };
  }
  async function exportEncryptedVault({ sections, passwords, cards, notes }, backupPassword, kdfSpec, opts = {}) {
    const payload = {
      format: "khazna-plain-json",
      version: 1,
      exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
      sections: sections.map((s) => ({ id: s.id, ...s.data })),
      passwords: passwords.map((p) => ({
        id: p.id,
        ...p.data,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt
      })),
      cards: cards.map((c) => ({ id: c.id, ...c.data })),
      notes: notes.map((n) => ({ id: n.id, ...n.data }))
    };
    return encryptVaultBackup(payload, backupPassword, kdfSpec, opts);
  }
  function exportPlainJson({ sections, passwords, cards, notes }) {
    const sectionById = new Map(sections.map((s) => [s.id, s.data?.name || ""]));
    return JSON.stringify(
      {
        format: "khazna-plain-json",
        version: 1,
        exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
        sections: sections.map((s) => ({
          id: s.id,
          name: s.data?.name || "",
          emoji: s.data?.emoji || "\u{1F510}",
          color: s.data?.color || "#38bdf8",
          order: s.data?.order ?? 0
        })),
        passwords: passwords.map((p) => ({
          title: p.data?.title || "",
          url: p.data?.url || "",
          username: p.data?.username || "",
          password: p.data?.password || "",
          notes: p.data?.notes || "",
          folder: sectionById.get(p.data?.sectionId) || "",
          favorite: Boolean(p.data?.favorite),
          passwordHistory: p.data?.passwordHistory || [],
          createdAt: p.createdAt,
          updatedAt: p.updatedAt
        })),
        cards: cards.map((c) => ({ ...c.data })),
        notes: notes.map((n) => ({ ...n.data }))
      },
      null,
      2
    );
  }
  function exportChromeCsv(passwords) {
    const headers = ["name", "url", "username", "password", "note"];
    const rows = passwords.map((p) => [
      p.data?.title || "",
      p.data?.url || "",
      p.data?.username || "",
      p.data?.password || "",
      p.data?.notes || ""
    ]);
    return serializeCsv(headers, rows, ",");
  }
  function exportBitwardenJson({ sections, passwords, cards, notes }) {
    const folders = sections.map((s) => ({ id: s.id, name: s.data?.name || "Folder" }));
    const items = [];
    for (const p of passwords) {
      items.push({
        id: p.id || randomId("bw"),
        folderId: p.data?.sectionId || null,
        type: 1,
        name: p.data?.title || "",
        notes: p.data?.notes || null,
        favorite: Boolean(p.data?.favorite),
        login: {
          uris: p.data?.url ? [{ match: null, uri: p.data.url }] : [],
          username: p.data?.username || "",
          password: p.data?.password || "",
          totp: null
        }
      });
    }
    for (const c of cards) {
      const [mm = "", yy = ""] = String(c.data?.expiry || "").split("/");
      items.push({
        id: c.id || randomId("bw"),
        folderId: null,
        type: 3,
        name: c.data?.cardName || "Card",
        notes: c.data?.notes || null,
        favorite: false,
        card: {
          cardholderName: c.data?.holderName || "",
          brand: c.data?.brandOverride || "Other",
          number: c.data?.number || "",
          expMonth: mm,
          expYear: yy ? yy.length === 2 ? `20${yy}` : yy : "",
          code: c.data?.cvv || ""
        }
      });
    }
    for (const n of notes) {
      items.push({
        id: n.id || randomId("bw"),
        folderId: null,
        type: 2,
        name: n.data?.title || "Note",
        notes: n.data?.body || "",
        favorite: Boolean(n.data?.pinned),
        secureNote: { type: 0 }
      });
    }
    return JSON.stringify({ encrypted: false, folders, items }, null, 2);
  }
  async function exportBestEffortSpass({ passwords, cards, notes }, exportPassword) {
    return exportSpass(
      {
        passwords: passwords.map((p) => p.data || p),
        cards: cards.map((c) => c.data || c),
        notes: notes.map((n) => n.data || n)
      },
      exportPassword
    );
  }

  // src/domain/search.js
  var ARABIC_DIACRITICS_RE = /[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED\u0640]/g;
  function normalizeSearchText(input) {
    return String(input || "").normalize("NFKD").replace(ARABIC_DIACRITICS_RE, "").replace(/[أإآٱ]/g, "\u0627").replace(/ة/g, "\u0647").replace(/ى/g, "\u064A").replace(/ؤ/g, "\u0648").replace(/ئ/g, "\u064A").toLowerCase().trim();
  }
  function matchesQuery(query, fields) {
    const normQ = normalizeSearchText(query);
    if (!normQ) return true;
    const tokens = normQ.split(/\s+/).filter(Boolean);
    const haystack = fields.map((f) => normalizeSearchText(f)).join(" ");
    return tokens.every((tok) => haystack.includes(tok));
  }
  function filterAndSortPasswords(entries, {
    query = "",
    sectionId = "all",
    favoritesOnly = false,
    duplicatesOnly = false,
    sortBy = "updated-desc"
  } = {}) {
    let duplicateIdSet = null;
    if (duplicatesOnly) {
      duplicateIdSet = findDuplicateEntryIds(entries);
    }
    const filtered = entries.filter((entry) => {
      const d = entry.data || {};
      if (sectionId && sectionId !== "all" && d.sectionId !== sectionId) return false;
      if (favoritesOnly && !d.favorite) return false;
      if (duplicateIdSet && !duplicateIdSet.has(entry.id)) return false;
      if (query) {
        return matchesQuery(query, [d.title, d.username, d.url, d.notes]);
      }
      return true;
    });
    filtered.sort((a, b) => {
      const da = a.data || {};
      const db = b.data || {};
      if (sortBy === "title-asc") {
        return String(da.title || "").localeCompare(String(db.title || ""), "ar");
      }
      if (sortBy === "title-desc") {
        return String(db.title || "").localeCompare(String(da.title || ""), "ar");
      }
      if (sortBy === "created-desc") {
        return String(b.createdAt || "").localeCompare(String(a.createdAt || ""));
      }
      if (sortBy === "favorites-first") {
        if (Boolean(da.favorite) !== Boolean(db.favorite)) return da.favorite ? -1 : 1;
        return String(b.updatedAt || "").localeCompare(String(a.updatedAt || ""));
      }
      return String(b.updatedAt || "").localeCompare(String(a.updatedAt || ""));
    });
    return filtered;
  }
  function findDuplicateEntryIds(entries) {
    const byKey = /* @__PURE__ */ new Map();
    const byPwd = /* @__PURE__ */ new Map();
    const dupIds = /* @__PURE__ */ new Set();
    for (const entry of entries) {
      const d = entry.data || {};
      const urlHost = extractHost(d.url);
      const user = normalizeSearchText(d.username);
      const title = normalizeSearchText(d.title);
      const identityKey = urlHost && user ? `u:${urlHost}|${user}` : title && user ? `t:${title}|${user}` : null;
      if (identityKey) {
        const list = byKey.get(identityKey) || [];
        list.push(entry.id);
        byKey.set(identityKey, list);
      }
      if (d.password && d.password.length >= 4) {
        const pList = byPwd.get(d.password) || [];
        pList.push(entry.id);
        byPwd.set(d.password, pList);
      }
    }
    for (const ids of byKey.values()) {
      if (ids.length > 1) ids.forEach((id) => dupIds.add(id));
    }
    for (const ids of byPwd.values()) {
      if (ids.length > 1) ids.forEach((id) => dupIds.add(id));
    }
    return dupIds;
  }
  function extractHost(rawUrl) {
    const str = String(rawUrl || "").trim();
    if (!str) return "";
    try {
      const withProto = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(str) ? str : `https://${str}`;
      const u = new URL(withProto);
      return u.hostname.replace(/^www\./i, "").toLowerCase();
    } catch {
      return str.toLowerCase();
    }
  }

  // src/import-export/manager.js
  var SECTION_ACCENTS = ["#38bdf8", "#10b981", "#a78bfa", "#f59e0b", "#f472b6", "#2dd4bf", "#fb7185"];
  function passwordMatchKey(item) {
    const host = extractHost(item.url);
    const user = normalizeSearchText(item.username);
    const title = normalizeSearchText(item.title);
    if (host && user) return `u:${host}|${user}`;
    return `t:${title}|${user}`;
  }
  function cardMatchKey(card) {
    const num = String(card.number || "").replace(/\D+/g, "");
    const label = normalizeSearchText(card.cardName);
    return num.length >= 4 ? `c:${num.slice(0, 6)}|${num.slice(-4)}|${card.expiry || ""}` : `cl:${label}`;
  }
  function noteMatchKey(note) {
    return `n:${normalizeSearchText(note.title)}|${normalizeSearchText((note.body || "").slice(0, 80))}`;
  }
  function buildImportPreview(bundle, existing = { sections: [], passwords: [], cards: [], notes: [] }) {
    const existingPwdKeys = /* @__PURE__ */ new Map();
    for (const p of existing.passwords) {
      existingPwdKeys.set(passwordMatchKey(p.data || {}), p);
    }
    const existingCardKeys = /* @__PURE__ */ new Map();
    for (const c of existing.cards) {
      existingCardKeys.set(cardMatchKey(c.data || {}), c);
    }
    const existingNoteKeys = /* @__PURE__ */ new Map();
    for (const n of existing.notes) {
      existingNoteKeys.set(noteMatchKey(n.data || {}), n);
    }
    let duplicatePasswords = 0;
    for (const p of bundle.passwords || []) {
      if (existingPwdKeys.has(passwordMatchKey(p))) duplicatePasswords++;
    }
    let duplicateCards = 0;
    for (const c of bundle.cards || []) {
      if (existingCardKeys.has(cardMatchKey(c))) duplicateCards++;
    }
    let duplicateNotes = 0;
    for (const n of bundle.notes || []) {
      if (existingNoteKeys.has(noteMatchKey(n))) duplicateNotes++;
    }
    const detectedFolders = /* @__PURE__ */ new Set();
    for (const s of bundle.sections || []) {
      if (s?.name) detectedFolders.add(s.name);
    }
    for (const p of bundle.passwords || []) {
      if (p?.folder) detectedFolders.add(p.folder);
    }
    return {
      format: bundle.format,
      counts: {
        passwords: (bundle.passwords || []).length,
        cards: (bundle.cards || []).length,
        notes: (bundle.notes || []).length,
        sections: detectedFolders.size
      },
      duplicates: {
        passwords: duplicatePasswords,
        cards: duplicateCards,
        notes: duplicateNotes,
        total: duplicatePasswords + duplicateCards + duplicateNotes
      },
      folders: Array.from(detectedFolders),
      warnings: bundle.warnings || [],
      csvHeaders: bundle.csvHeaders || null,
      csvColumnMap: bundle.csvColumnMap || null
    };
  }
  async function commitImportTransaction({
    session: session2,
    bundle,
    sectionMode = "map-folders",
    targetSectionId = null,
    duplicateStrategy = "skip"
  }) {
    const existingSections = await session2.listRecords("section");
    const existingPasswords = await session2.listRecords("password");
    const existingCards = await session2.listRecords("card");
    const existingNotes = await session2.listRecords("note");
    const sectionByName = new Map(
      existingSections.map((s) => [normalizeSearchText(s.data?.name), s.id])
    );
    const existingPwdByKey = new Map(
      existingPasswords.map((p) => [passwordMatchKey(p.data || {}), p])
    );
    const existingCardByKey = new Map(
      existingCards.map((c) => [cardMatchKey(c.data || {}), c])
    );
    const existingNoteByKey = new Map(
      existingNotes.map((n) => [noteMatchKey(n.data || {}), n])
    );
    const itemsToEncrypt = [];
    let nextSectionOrder = existingSections.length;
    const fallbackSectionId = targetSectionId || existingSections[0]?.id || null;
    const resolveFolderSectionId = (folderName, sectionMeta = null) => {
      if (sectionMode === "single-section") {
        return fallbackSectionId;
      }
      const clean = String(folderName || "").trim();
      if (!clean) return fallbackSectionId;
      const norm = normalizeSearchText(clean);
      if (sectionByName.has(norm)) return sectionByName.get(norm);
      const newId = randomId("sec");
      sectionByName.set(norm, newId);
      itemsToEncrypt.push({
        id: newId,
        type: "section",
        data: {
          name: clean,
          emoji: sectionMeta?.emoji || "\u{1F4C1}",
          color: sectionMeta?.color || SECTION_ACCENTS[nextSectionOrder % SECTION_ACCENTS.length],
          order: nextSectionOrder++
        }
      });
      return newId;
    };
    if (sectionMode === "map-folders") {
      for (const sec of bundle.sections || []) {
        if (sec?.name) resolveFolderSectionId(sec.name, sec);
      }
    }
    const report = {
      added: { sections: 0, passwords: 0, cards: 0, notes: 0 },
      replaced: { passwords: 0, cards: 0, notes: 0 },
      skipped: { passwords: 0, cards: 0, notes: 0 },
      snapshotId: null
    };
    for (const p of bundle.passwords || []) {
      const key = passwordMatchKey(p);
      const existing = existingPwdByKey.get(key);
      const secId = resolveFolderSectionId(p.folder || p.sectionName || "");
      const payload = {
        title: String(p.title || "Untitled").trim(),
        sectionId: secId,
        username: String(p.username || ""),
        password: String(p.password || ""),
        url: String(p.url || ""),
        notes: String(p.notes || ""),
        favorite: Boolean(p.favorite),
        passwordUpdatedAt: p.updatedAt || (/* @__PURE__ */ new Date()).toISOString(),
        passwordHistory: Array.isArray(p.passwordHistory) ? p.passwordHistory.slice(0, 10) : []
      };
      if (existing) {
        if (duplicateStrategy === "skip") {
          report.skipped.passwords++;
          continue;
        }
        if (duplicateStrategy === "replace") {
          const hist = Array.isArray(existing.data?.passwordHistory) ? [...existing.data.passwordHistory] : [];
          if (existing.data?.password && existing.data.password !== payload.password) {
            hist.unshift({ value: existing.data.password, changedAt: (/* @__PURE__ */ new Date()).toISOString() });
          }
          payload.passwordHistory = hist.slice(0, 10);
          itemsToEncrypt.push({
            id: existing.id,
            type: "password",
            data: payload,
            createdAt: existing.createdAt
          });
          report.replaced.passwords++;
          continue;
        }
      }
      itemsToEncrypt.push({
        id: randomId("pwd"),
        type: "password",
        data: payload,
        createdAt: p.createdAt
      });
      report.added.passwords++;
    }
    for (const c of bundle.cards || []) {
      const key = cardMatchKey(c);
      const existing = existingCardByKey.get(key);
      const payload = {
        cardName: String(c.cardName || "Card").trim(),
        bankName: String(c.bankName || ""),
        holderName: String(c.holderName || ""),
        number: String(c.number || ""),
        expiry: String(c.expiry || ""),
        cvv: String(c.cvv || ""),
        pin: String(c.pin || ""),
        notes: String(c.notes || ""),
        theme: c.theme || "obsidian",
        brandOverride: c.brandOverride || "auto",
        partial: Boolean(c.partial || String(c.number || "").includes("*"))
      };
      if (existing) {
        if (duplicateStrategy === "skip") {
          report.skipped.cards++;
          continue;
        }
        if (duplicateStrategy === "replace") {
          itemsToEncrypt.push({ id: existing.id, type: "card", data: payload, createdAt: existing.createdAt });
          report.replaced.cards++;
          continue;
        }
      }
      itemsToEncrypt.push({ id: randomId("crd"), type: "card", data: payload });
      report.added.cards++;
    }
    for (const n of bundle.notes || []) {
      const key = noteMatchKey(n);
      const existing = existingNoteByKey.get(key);
      const payload = {
        title: String(n.title || "Note").trim(),
        body: String(n.body || ""),
        checklist: Array.isArray(n.checklist) ? n.checklist : [],
        pinned: Boolean(n.pinned)
      };
      if (existing) {
        if (duplicateStrategy === "skip") {
          report.skipped.notes++;
          continue;
        }
        if (duplicateStrategy === "replace") {
          itemsToEncrypt.push({ id: existing.id, type: "note", data: payload, createdAt: existing.createdAt });
          report.replaced.notes++;
          continue;
        }
      }
      itemsToEncrypt.push({ id: randomId("nte"), type: "note", data: payload });
      report.added.notes++;
    }
    report.added.sections = itemsToEncrypt.filter((i) => i.type === "section").length;
    const encryptedBatch = await session2.encryptBatchForAtomicWrite(itemsToEncrypt);
    const snapshotId = await session2.storage.atomicOperationWithSnapshot({
      reason: `import-${bundle.format}`,
      putRecords: encryptedBatch
    });
    report.snapshotId = snapshotId;
    return report;
  }

  // src/ui/import-export-sheet.js
  function openImportExportSheet({
    session: session2,
    lang,
    sections,
    passwords,
    cards,
    notes,
    initialTab = "import",
    initialPastedText = "",
    onChanged
  }) {
    let activeTab = initialTab;
    const bodyHost = el("div", { class: "settings-group" });
    const tabImp = el("button", { type: "button", class: `seg-btn ${activeTab === "import" ? "is-active" : ""}` }, t(lang, "tabImport"));
    const tabExp = el("button", { type: "button", class: `seg-btn ${activeTab === "export" ? "is-active" : ""}` }, t(lang, "tabExport"));
    const renderTab = () => {
      while (bodyHost.firstChild) bodyHost.removeChild(bodyHost.firstChild);
      tabImp.classList.toggle("is-active", activeTab === "import");
      tabExp.classList.toggle("is-active", activeTab === "export");
      if (activeTab === "import") {
        renderImportTab();
      } else {
        renderExportTab();
      }
    };
    const renderImportTab = () => {
      let selectedFileName = "";
      let parsedBundle = null;
      let customCsvMapping = null;
      let lastSnapshotId = null;
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const textIn = el("textarea", {
        id: "imp-text",
        class: "textarea ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: "name,url,username,password,note..."
      }, initialPastedText || "");
      const pwdIn = el("input", {
        id: "imp-pwd",
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: t(lang, "importPwdLabel")
      });
      const fileLabel = el("span", { class: "settings-row-desc" }, "");
      const fileInput = el("input", {
        type: "file",
        class: "sr-only",
        accept: ".vault,.spass,.json,.csv,.txt",
        onChange: async (e) => {
          const file = e.target.files?.[0];
          if (!file) return;
          selectedFileName = file.name;
          fileLabel.textContent = file.name;
          textIn.value = await file.text();
        }
      });
      const previewHost = el("div", { class: "settings-group" });
      const runAnalyze = async () => {
        errBox.classList.add("hidden");
        while (previewHost.firstChild) previewHost.removeChild(previewHost.firstChild);
        try {
          parsedBundle = await parseImportSource({
            rawText: textIn.value,
            fileName: selectedFileName,
            password: pwdIn.value,
            customCsvMapping
          });
          const preview = buildImportPreview(parsedBundle, { sections, passwords, cards, notes });
          previewHost.appendChild(
            el(
              "div",
              { class: "banner banner-info" },
              el(
                "span",
                null,
                `${preview.format} \u2014 \u{1F511} ${preview.counts.passwords} \u2022 \u{1F4B3} ${preview.counts.cards} \u2022 \u{1F4DD} ${preview.counts.notes} (${t(lang, "duplicates")}: ${preview.duplicates.total})`
              )
            )
          );
          if (preview.format === "spass") {
            previewHost.appendChild(el("div", { class: "banner banner-warn" }, el("span", null, t(lang, "spassHonestNote"))));
          }
          if (parsedBundle.isCsv && preview.csvHeaders) {
            const mapperBox = el("details", { class: "glass-card glass-card-compact" }, el("summary", null, lang === "en" ? "CSV Column Mapping (Manual Override)" : "\u062A\u0639\u064A\u064A\u0646 \u0623\u0639\u0645\u062F\u0629 CSV (\u062A\u0639\u062F\u064A\u0644 \u064A\u062F\u0648\u064A)"));
            const mapGrid = el("div", { class: "settings-group" });
            const nextMap = { ...preview.csvColumnMap };
            preview.csvHeaders.forEach((hdr, idx) => {
              const sel = el(
                "select",
                {
                  class: "select",
                  "aria-label": hdr,
                  onChange: (e) => {
                    nextMap[idx] = e.target.value;
                    customCsvMapping = nextMap;
                    runAnalyze();
                  }
                },
                ...CSV_TARGET_FIELDS.map((f) => el("option", { value: f, selected: nextMap[idx] === f }, f))
              );
              mapGrid.appendChild(el("div", { class: "input-row" }, el("span", { class: "ltr-inline mono" }, hdr), sel));
            });
            mapperBox.appendChild(mapGrid);
            previewHost.appendChild(mapperBox);
          }
          const sectionModeSel = el(
            "select",
            { class: "select", "aria-label": "Section mapping mode" },
            el("option", { value: "map-folders" }, lang === "en" ? "Map source folders to sections" : "\u062A\u062D\u0648\u064A\u0644 \u0645\u062C\u0644\u062F\u0627\u062A \u0627\u0644\u0645\u0635\u062F\u0631 \u0625\u0644\u0649 \u0623\u0642\u0633\u0627\u0645 \u062A\u0644\u0642\u0627\u0626\u064A\u0627\u064B"),
            el("option", { value: "single-section" }, lang === "en" ? "Import all into one section" : "\u0627\u0633\u062A\u064A\u0631\u0627\u062F \u0627\u0644\u0643\u0644 \u062F\u0627\u062E\u0644 \u0642\u0633\u0645 \u0645\u062D\u062F\u062F")
          );
          const targetSecSel = el(
            "select",
            { class: "select", "aria-label": t(lang, "sectionLabel") },
            ...sections.map((s) => el("option", { value: s.id }, `${s.data?.emoji || "\u{1F4C1}"} ${s.data?.name || ""}`))
          );
          const dupSel = el(
            "select",
            { class: "select", "aria-label": "Duplicate strategy" },
            el("option", { value: "skip" }, lang === "en" ? "Duplicates: Skip" : "\u0627\u0644\u0645\u0643\u0631\u0631: \u062A\u062E\u0637\u0651\u064A"),
            el("option", { value: "replace" }, lang === "en" ? "Duplicates: Replace existing" : "\u0627\u0644\u0645\u0643\u0631\u0631: \u0627\u0633\u062A\u0628\u062F\u0627\u0644 \u0627\u0644\u062D\u0627\u0644\u064A"),
            el("option", { value: "keep-both" }, lang === "en" ? "Duplicates: Keep both" : "\u0627\u0644\u0645\u0643\u0631\u0631: \u0627\u0644\u0627\u062D\u062A\u0641\u0627\u0638 \u0628\u0627\u0644\u0627\u062B\u0646\u064A\u0646")
          );
          const commitBtn = el(
            "button",
            {
              type: "button",
              class: "btn btn-primary btn-block",
              onClick: async () => {
                commitBtn.disabled = true;
                try {
                  const report = await commitImportTransaction({
                    session: session2,
                    bundle: parsedBundle,
                    sectionMode: sectionModeSel.value,
                    targetSectionId: targetSecSel.value || null,
                    duplicateStrategy: dupSel.value
                  });
                  lastSnapshotId = report.snapshotId;
                  textIn.value = "";
                  pwdIn.value = "";
                  parsedBundle = null;
                  while (previewHost.firstChild) previewHost.removeChild(previewHost.firstChild);
                  previewHost.appendChild(
                    el(
                      "div",
                      { class: "banner banner-success" },
                      el(
                        "span",
                        null,
                        lang === "en" ? `Imported: +${report.added.passwords} passwords, +${report.added.cards} cards, +${report.added.notes} notes (skipped: ${report.skipped.passwords + report.skipped.cards + report.skipped.notes}).` : `\u062A\u0645 \u0627\u0644\u0627\u0633\u062A\u064A\u0631\u0627\u062F: +${report.added.passwords} \u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631\u060C +${report.added.cards} \u0628\u0637\u0627\u0642\u0629\u060C +${report.added.notes} \u0645\u0644\u0627\u062D\u0638\u0629 (\u062A\u0645 \u062A\u062E\u0637\u064A: ${report.skipped.passwords + report.skipped.cards + report.skipped.notes}).`
                      )
                    )
                  );
                  previewHost.appendChild(el("div", { class: "banner banner-warn" }, el("span", null, t(lang, "deletePlaintextReminder"))));
                  previewHost.appendChild(
                    el(
                      "button",
                      {
                        type: "button",
                        class: "btn btn-danger btn-block",
                        onClick: async () => {
                          if (!lastSnapshotId) return;
                          await session2.storage.restoreSnapshot(lastSnapshotId);
                          showToast(t(lang, "undoImportBtn"), "info");
                          onChanged && await onChanged();
                          sheet.close();
                        }
                      },
                      t(lang, "undoImportBtn")
                    )
                  );
                  onChanged && await onChanged();
                } catch (err) {
                  errBox.textContent = formatError(err, lang);
                  errBox.classList.remove("hidden");
                  commitBtn.disabled = false;
                }
              }
            },
            svgIcon("upload", 18),
            t(lang, "commitImportBtn")
          );
          previewHost.appendChild(el("div", { class: "form-grid-2" }, sectionModeSel, targetSecSel));
          previewHost.appendChild(dupSel);
          previewHost.appendChild(commitBtn);
        } catch (err) {
          errBox.textContent = formatError(err, lang);
          errBox.classList.remove("hidden");
        }
      };
      bodyHost.appendChild(errBox);
      bodyHost.appendChild(
        el(
          "div",
          { class: "input-row" },
          fileInput,
          el("button", { type: "button", class: "btn", onClick: () => fileInput.click() }, svgIcon("upload", 16), t(lang, "pickFileBtn")),
          fileLabel
        )
      );
      bodyHost.appendChild(el("div", { class: "field" }, el("label", { class: "field-label", for: "imp-text" }, t(lang, "pasteTextLabel")), textIn));
      bodyHost.appendChild(el("div", { class: "field" }, el("label", { class: "field-label", for: "imp-pwd" }, t(lang, "importPwdLabel")), pwdIn));
      bodyHost.appendChild(el("button", { type: "button", class: "btn btn-primary btn-block", onClick: runAnalyze }, t(lang, "analyzeImportBtn")));
      bodyHost.appendChild(previewHost);
    };
    const renderExportTab = () => {
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const fmtSel = el(
        "select",
        { id: "exp-fmt", class: "select" },
        el("option", { value: "vault" }, lang === "en" ? "Encrypted Backup (.vault) \u2014 Recommended" : "\u0646\u0633\u062E\u0629 \u0645\u0634\u0641\u0651\u0631\u0629 (.vault) \u2014 \u0627\u0644\u0645\u0648\u0635\u0649 \u0628\u0647"),
        el("option", { value: "plain-json" }, lang === "en" ? "Plain JSON (Unencrypted)" : "JSON \u0646\u0635\u064A (\u063A\u064A\u0631 \u0645\u0634\u0641\u0651\u0631)"),
        el("option", { value: "chrome-csv" }, lang === "en" ? "Chrome-Compatible CSV (Unencrypted)" : "CSV \u0645\u062A\u0648\u0627\u0641\u0642 \u0645\u0639 \u0643\u0631\u0648\u0645 (\u063A\u064A\u0631 \u0645\u0634\u0641\u0651\u0631)"),
        el("option", { value: "bitwarden-json" }, lang === "en" ? "Bitwarden JSON (Unencrypted)" : "Bitwarden JSON (\u063A\u064A\u0631 \u0645\u0634\u0641\u0651\u0631)"),
        el("option", { value: "spass" }, lang === "en" ? "Samsung Pass (.spass \u2014 Best Effort)" : "Samsung Pass (.spass \u2014 \u0623\u0641\u0636\u0644 \u062C\u0647\u062F)")
      );
      const scopeSel = el(
        "select",
        { id: "exp-scope", class: "select" },
        el("option", { value: "all" }, lang === "en" ? "Entire Vault" : "\u0643\u0627\u0645\u0644 \u0627\u0644\u062E\u0632\u0646\u0629"),
        ...sections.map((s) => el("option", { value: s.id }, `${s.data?.emoji || "\u{1F4C1}"} ${s.data?.name || ""}`))
      );
      const expPwdIn = el("input", {
        id: "exp-pwd",
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: lang === "en" ? "Backup password (min 8 chars)" : "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0646\u0633\u062E\u0629 \u0627\u0644\u0627\u062D\u062A\u064A\u0627\u0637\u064A\u0629 (\u0668 \u0623\u062D\u0631\u0641+)"
      });
      const plainWarnBox = el("div", { class: "banner banner-danger hidden" }, el("span", null, t(lang, "plainExportWarn")));
      const confirmPlainCheck = el("input", { type: "checkbox" });
      const confirmPlainRow = el(
        "label",
        { class: "checkbox-row hidden" },
        confirmPlainCheck,
        el("span", null, lang === "en" ? "I understand this export is unencrypted." : "\u0623\u0641\u0647\u0645 \u0623\u0646 \u0647\u0630\u0627 \u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u063A\u064A\u0631 \u0645\u0634\u0641\u0651\u0631 \u0648\u0633\u0623\u062D\u0630\u0641\u0647 \u0641\u0648\u0631\u0627\u064B \u0628\u0639\u062F \u0627\u0644\u0627\u0633\u062A\u062E\u062F\u0627\u0645.")
      );
      const syncFormatUi = () => {
        const f = fmtSel.value;
        const isPlain = f === "plain-json" || f === "chrome-csv" || f === "bitwarden-json";
        plainWarnBox.classList.toggle("hidden", !isPlain);
        confirmPlainRow.classList.toggle("hidden", !isPlain);
        expPwdIn.parentElement.classList.toggle("hidden", isPlain);
      };
      fmtSel.addEventListener("change", syncFormatUi);
      const buildExportBlob = async () => {
        errBox.classList.add("hidden");
        const f = fmtSel.value;
        const isPlain = f === "plain-json" || f === "chrome-csv" || f === "bitwarden-json";
        if (isPlain && !confirmPlainCheck.checked) {
          throw new Error(lang === "en" ? "Please confirm the unencrypted export warning." : "\u064A\u0631\u062C\u0649 \u062A\u0623\u0643\u064A\u062F \u0641\u0647\u0645 \u062A\u062D\u0630\u064A\u0631 \u0627\u0644\u062A\u0635\u062F\u064A\u0631 \u063A\u064A\u0631 \u0627\u0644\u0645\u0634\u0641\u0651\u0631.");
        }
        const ok = await requestReauth({ session: session2, lang });
        if (!ok) return null;
        const scope = scopeSel.value;
        const scopedPasswords = scope === "all" ? passwords : passwords.filter((p) => p.data?.sectionId === scope);
        const scopedSections = scope === "all" ? sections : sections.filter((s) => s.id === scope);
        const scopedCards = scope === "all" ? cards : [];
        const scopedNotes = scope === "all" ? notes : [];
        const stamp = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
        let text;
        let fileName;
        let mime = "application/json";
        if (f === "vault") {
          const kdfSpec = { kdf: session2.header.kdf, params: session2.header.kdfParams };
          text = await exportEncryptedVault(
            { sections: scopedSections, passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes },
            expPwdIn.value,
            kdfSpec,
            { enforceMinimums: false }
          );
          fileName = `khazna-backup-${stamp}.vault`;
        } else if (f === "spass") {
          text = await exportBestEffortSpass(
            { passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes },
            expPwdIn.value
          );
          fileName = `khazna-${stamp}.spass`;
          mime = "text/plain";
        } else if (f === "chrome-csv") {
          text = exportChromeCsv(scopedPasswords);
          fileName = `khazna-chrome-${stamp}.csv`;
          mime = "text/csv";
        } else if (f === "bitwarden-json") {
          text = exportBitwardenJson({ sections: scopedSections, passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes });
          fileName = `khazna-bitwarden-${stamp}.json`;
        } else {
          text = exportPlainJson({ sections: scopedSections, passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes });
          fileName = `khazna-plain-${stamp}.json`;
        }
        expPwdIn.value = "";
        await session2.updateSettings({ lastBackupAt: (/* @__PURE__ */ new Date()).toISOString() });
        return { text, fileName, mime };
      };
      const triggerDownload = async () => {
        try {
          const res = await buildExportBlob();
          if (!res) return;
          const blob = new Blob([res.text], { type: res.mime });
          const url = URL.createObjectURL(blob);
          const a = el("a", { href: url, download: res.fileName });
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 5e3);
          triggerHaptic();
          showToast(`${res.fileName}`, "success");
        } catch (err) {
          errBox.textContent = formatError(err, lang);
          errBox.classList.remove("hidden");
        }
      };
      const triggerShare = async () => {
        try {
          const res = await buildExportBlob();
          if (!res) return;
          const file = new File([res.text], res.fileName, { type: res.mime });
          if (navigator.share && (!navigator.canShare || navigator.canShare({ files: [file] }))) {
            await navigator.share({ title: "Khazna Backup", files: [file] });
          } else {
            showToast(lang === "en" ? "Web Share is unavailable on this browser \u2014 use Download." : "\u0627\u0644\u0645\u0634\u0627\u0631\u0643\u0629 \u063A\u064A\u0631 \u0645\u062F\u0639\u0648\u0645\u0629 \u0641\u064A \u0647\u0630\u0627 \u0627\u0644\u0645\u062A\u0635\u0641\u062D \u2014 \u0627\u0633\u062A\u062E\u062F\u0645 \u0627\u0644\u062A\u0646\u0632\u064A\u0644.", "warn");
          }
        } catch (err) {
          if (err?.name !== "AbortError") {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove("hidden");
          }
        }
      };
      const triggerCopy = async () => {
        try {
          const res = await buildExportBlob();
          if (!res) return;
          await session2.clipboard.copySecret(res.text, session2.settings?.clipboardClearSec ?? 30);
          triggerHaptic();
          showToast(t(lang, "copiedToast"), "success");
        } catch (err) {
          errBox.textContent = formatError(err, lang);
          errBox.classList.remove("hidden");
        }
      };
      bodyHost.appendChild(errBox);
      bodyHost.appendChild(el("div", { class: "field" }, el("label", { class: "field-label", for: "exp-fmt" }, lang === "en" ? "Format" : "\u0635\u064A\u063A\u0629 \u0627\u0644\u062A\u0635\u062F\u064A\u0631"), fmtSel));
      bodyHost.appendChild(el("div", { class: "field" }, el("label", { class: "field-label", for: "exp-scope" }, lang === "en" ? "Scope" : "\u0646\u0637\u0627\u0642 \u0627\u0644\u062A\u0635\u062F\u064A\u0631"), scopeSel));
      bodyHost.appendChild(el("div", { class: "field" }, el("label", { class: "field-label", for: "exp-pwd" }, lang === "en" ? "Backup Password" : "\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0646\u0633\u062E\u0629"), expPwdIn));
      bodyHost.appendChild(plainWarnBox);
      bodyHost.appendChild(confirmPlainRow);
      bodyHost.appendChild(
        el(
          "div",
          { class: "settings-group" },
          el("button", { type: "button", class: "btn btn-primary btn-block", onClick: triggerDownload }, svgIcon("download", 18), lang === "en" ? "Download File" : "\u062A\u0646\u0632\u064A\u0644 \u0627\u0644\u0645\u0644\u0641"),
          el(
            "div",
            { class: "form-grid-2" },
            el("button", { type: "button", class: "btn", onClick: triggerShare }, lang === "en" ? "Share (Drive / WhatsApp)" : "\u0645\u0634\u0627\u0631\u0643\u0629 (Drive / \u0648\u0627\u062A\u0633\u0627\u0628)"),
            el("button", { type: "button", class: "btn", onClick: triggerCopy }, svgIcon("copy", 16), lang === "en" ? "Copy Text" : "\u0646\u0633\u062E \u0643\u0646\u0635")
          )
        )
      );
      syncFormatUi();
    };
    tabImp.addEventListener("click", () => {
      activeTab = "import";
      renderTab();
    });
    tabExp.addEventListener("click", () => {
      activeTab = "export";
      renderTab();
    });
    renderTab();
    const content = el(
      "div",
      { class: "settings-group" },
      el("div", { class: "segmented" }, tabImp, tabExp),
      bodyHost
    );
    const sheet = openBottomSheet({ title: t(lang, "importTitle"), content });
    return sheet;
  }

  // src/ui/notes-view.js
  var DRAFT_RECORD_ID = "draft_note_active";
  function renderNotesView({ session: session2, lang, notes, query, onQueryChange, onRefresh }) {
    const container = el("div", { class: "settings-group view-enter" });
    const searchIn = el("input", {
      type: "search",
      class: "input",
      value: query || "",
      placeholder: t(lang, "searchPlaceholder"),
      autocomplete: "off",
      onInput: (e) => onQueryChange(e.target.value)
    });
    container.appendChild(
      el("div", { class: "search-wrap" }, el("span", { class: "search-icon" }, svgIcon("search", 18)), searchIn)
    );
    const filtered = notes.filter((n) => {
      const d = n.data || {};
      const clText = (d.checklist || []).map((c) => c.text).join(" ");
      return matchesQuery(query, [d.title, d.body, clText]);
    }).sort((a, b) => {
      if (Boolean(a.data?.pinned) !== Boolean(b.data?.pinned)) return a.data?.pinned ? -1 : 1;
      return String(b.updatedAt || "").localeCompare(String(a.updatedAt || ""));
    });
    if (filtered.length === 0) {
      container.appendChild(
        el(
          "div",
          { class: "glass-card empty-state" },
          svgIcon("note", 38),
          el("h3", null, t(lang, "emptyNotes")),
          el("p", null, t(lang, "emptyNotesSub"))
        )
      );
      return container;
    }
    const grid = el("div", { class: "notes-grid", "data-testid": "notes-grid" });
    for (const note of filtered) {
      const d = note.data || {};
      const checklist = Array.isArray(d.checklist) ? d.checklist : [];
      const copyFullNote = async () => {
        const lines = [d.title || ""];
        if (d.body) lines.push(d.body);
        if (checklist.length) {
          lines.push(...checklist.map((i) => `${i.done ? "[x]" : "[ ]"} ${i.text}`));
        }
        try {
          await session2.clipboard.copySecret(lines.join("\n").trim(), session2.settings?.clipboardClearSec ?? 30);
          triggerHaptic();
          showToast(t(lang, "copiedToast"), "success");
        } catch (err) {
          showToast(formatError(err, lang), "error");
        }
      };
      const clNodes = checklist.slice(0, 4).map(
        (item, idx) => el(
          "label",
          { class: `checklist-item ${item.done ? "is-done" : ""}`.trim() },
          el("input", {
            type: "checkbox",
            checked: Boolean(item.done),
            onChange: async (e) => {
              const nextList = checklist.map((c, i) => i === idx ? { ...c, done: e.target.checked } : c);
              await session2.saveRecord({
                id: note.id,
                type: "note",
                createdAt: note.createdAt,
                data: { ...d, checklist: nextList }
              });
              await onRefresh();
            }
          }),
          el("span", null, item.text)
        )
      );
      const card = el(
        "article",
        { class: "glass-card note-card stagger-item" },
        el(
          "div",
          { class: "entry-top" },
          el("h3", { class: "entry-title" }, d.pinned ? "\u{1F4CC} " : "", d.title || "Untitled"),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-icon btn-ghost",
              "aria-label": `${t(lang, "pinNote")} ${d.title}`,
              onClick: async () => {
                await session2.saveRecord({
                  id: note.id,
                  type: "note",
                  createdAt: note.createdAt,
                  data: { ...d, pinned: !d.pinned }
                });
                await onRefresh();
              }
            },
            svgIcon("pin", 17, Boolean(d.pinned))
          )
        ),
        d.body ? el("p", { class: "note-body-preview" }, d.body) : null,
        clNodes.length ? el("div", { class: "settings-group" }, ...clNodes) : null,
        el(
          "div",
          { class: "entry-actions-row" },
          el("button", { type: "button", class: "btn btn-sm", onClick: copyFullNote }, svgIcon("copy", 14), t(lang, "copyAll")),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": `${t(lang, "edit")} ${d.title}`,
              onClick: () => openNoteEditorSheet({ session: session2, lang, note, onSaved: onRefresh })
            },
            svgIcon("edit", 14),
            t(lang, "edit")
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm btn-danger",
              "aria-label": `${t(lang, "delete")} ${d.title}`,
              onClick: async () => {
                await session2.trashRecord(note.id);
                await onRefresh();
              }
            },
            svgIcon("trash", 14)
          )
        )
      );
      grid.appendChild(card);
    }
    container.appendChild(grid);
    return container;
  }
  async function openNoteEditorSheet({ session: session2, lang, note = null, onSaved }) {
    let initialData = note?.data || { title: "", body: "", checklist: [], pinned: false };
    if (!note) {
      try {
        const drafts = await session2.listRecords("draft");
        const existingDraft = drafts.find((d) => d.id === DRAFT_RECORD_ID);
        if (existingDraft?.data && (existingDraft.data.title || existingDraft.data.body || existingDraft.data.checklist?.length)) {
          initialData = existingDraft.data;
        }
      } catch {
      }
    }
    const checklist = Array.isArray(initialData.checklist) ? initialData.checklist.map((c) => ({ ...c })) : [];
    const draftStatus = el("span", { class: "settings-row-desc" }, "");
    let autosaveTimer = null;
    const scheduleAutosave = () => {
      if (note) return;
      if (autosaveTimer) clearTimeout(autosaveTimer);
      autosaveTimer = setTimeout(async () => {
        try {
          await session2.saveRecord({
            id: DRAFT_RECORD_ID,
            type: "draft",
            data: {
              title: titleIn.value,
              body: bodyIn.value,
              checklist,
              pinned: pinCheck.checked
            }
          });
          draftStatus.textContent = `\u2713 ${t(lang, "draftSaved")}`;
        } catch {
        }
      }, 600);
    };
    const titleIn = el("input", {
      id: "ne-title",
      type: "text",
      class: "input",
      value: initialData.title || "",
      required: true,
      autocomplete: "off",
      onInput: scheduleAutosave
    });
    const bodyIn = el("textarea", {
      id: "ne-body",
      class: "textarea",
      autocomplete: "off",
      spellcheck: "false",
      onInput: scheduleAutosave
    }, initialData.body || "");
    const pinCheck = el("input", {
      type: "checkbox",
      checked: Boolean(initialData.pinned),
      onChange: scheduleAutosave
    });
    const clHost = el("div", { class: "settings-group" });
    const renderChecklistEditor = () => {
      while (clHost.firstChild) clHost.removeChild(clHost.firstChild);
      checklist.forEach((item, idx) => {
        clHost.appendChild(
          el(
            "div",
            { class: "input-row" },
            el("input", {
              type: "checkbox",
              checked: Boolean(item.done),
              onChange: (e) => {
                item.done = e.target.checked;
                scheduleAutosave();
              }
            }),
            el("input", {
              type: "text",
              class: "input",
              value: item.text,
              autocomplete: "off",
              onInput: (e) => {
                item.text = e.target.value;
                scheduleAutosave();
              }
            }),
            el(
              "button",
              {
                type: "button",
                class: "btn btn-icon btn-danger",
                "aria-label": "Remove item",
                onClick: () => {
                  checklist.splice(idx, 1);
                  renderChecklistEditor();
                  scheduleAutosave();
                }
              },
              svgIcon("close", 16)
            )
          )
        );
      });
    };
    renderChecklistEditor();
    const addItemBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-sm",
        onClick: () => {
          checklist.push({ text: "", done: false });
          renderChecklistEditor();
          scheduleAutosave();
        }
      },
      svgIcon("plus", 15),
      t(lang, "addChecklistItem")
    );
    const form = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          if (autosaveTimer) clearTimeout(autosaveTimer);
          const title = titleIn.value.trim();
          if (!title) return;
          await session2.saveRecord({
            id: note?.id || null,
            type: "note",
            createdAt: note?.createdAt,
            data: {
              title,
              body: bodyIn.value,
              checklist: checklist.filter((c) => c.text.trim() !== ""),
              pinned: pinCheck.checked
            }
          });
          if (!note) {
            await session2.permanentlyDeleteRecord(DRAFT_RECORD_ID).catch(() => {
            });
          }
          sheet.close();
          showToast(t(lang, "save"), "success");
          onSaved && await onSaved();
        }
      },
      el("div", { class: "field" }, el("label", { class: "field-label", for: "ne-title" }, el("span", null, t(lang, "noteTitleLabel")), draftStatus), titleIn),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "ne-body" }, t(lang, "noteBodyLabel")), bodyIn),
      el("div", { class: "field" }, el("div", { class: "field-label" }, el("span", null, t(lang, "checklistLabel")), addItemBtn), clHost),
      el("label", { class: "checkbox-row" }, pinCheck, el("span", null, t(lang, "pinNote"))),
      el(
        "div",
        { class: "form-grid-2" },
        el("button", { type: "button", class: "btn", onClick: () => sheet.close() }, t(lang, "cancel")),
        el("button", { type: "submit", class: "btn btn-primary" }, t(lang, "save"))
      )
    );
    const sheet = openBottomSheet({
      title: note ? t(lang, "editNote") : t(lang, "addNote"),
      content: form,
      onClose: () => {
        if (autosaveTimer) clearTimeout(autosaveTimer);
      }
    });
  }

  // src/ui/generator-sheet.js
  function openGeneratorSheet({ session: session2, lang, onSelect = null }) {
    let mode = "password";
    let length = 20;
    let wordCount = 6;
    let lower = true;
    let upper = true;
    let digits = true;
    let symbols = true;
    let excludeLookalikes = false;
    let currentValue = "";
    const previewNode = el("div", { class: "recovery-key-display", "data-testid": "generated-password" });
    const meterWrap = el(
      "div",
      { class: "strength-meter strength-4" },
      el(
        "div",
        { class: "strength-bars" },
        el("div", { class: "strength-bar" }),
        el("div", { class: "strength-bar" }),
        el("div", { class: "strength-bar" }),
        el("div", { class: "strength-bar" })
      ),
      el("div", { class: "strength-caption" })
    );
    const regen = () => {
      try {
        currentValue = mode === "password" ? generatePassword({ length, lower, upper, digits, symbols, excludeLookalikes }) : generatePassphrase({ wordCount, separator: "-", capitalize: true, includeNumber: true });
        previewNode.textContent = currentValue;
        const st = evaluatePasswordStrength(currentValue);
        meterWrap.className = `strength-meter strength-${st.score}`;
        const cap = meterWrap.querySelector(".strength-caption");
        cap.textContent = `${lang === "en" ? st.labelEn : st.labelAr} (${st.entropyBits} bits)`;
      } catch {
      }
    };
    const optionsHost = el("div", { class: "settings-group" });
    const renderOptions = () => {
      while (optionsHost.firstChild) optionsHost.removeChild(optionsHost.firstChild);
      if (mode === "password") {
        const lenVal = el("span", { class: "mono" }, String(length));
        const range = el("input", {
          type: "range",
          min: 8,
          max: 64,
          value: length,
          onInput: (e) => {
            length = parseInt(e.target.value, 10);
            lenVal.textContent = String(length);
            regen();
          }
        });
        optionsHost.appendChild(
          el(
            "div",
            { class: "field" },
            el("label", { class: "field-label" }, el("span", null, t(lang, "genLength")), lenVal),
            range
          )
        );
        const mkCheck = (label, checked, onChange) => {
          const cb = el("input", {
            type: "checkbox",
            checked,
            onChange: (e) => {
              onChange(e.target.checked);
              if (!lower && !upper && !digits && !symbols) {
                lower = true;
                renderOptions();
              }
              regen();
            }
          });
          return el("label", { class: "checkbox-row" }, cb, el("span", null, label));
        };
        optionsHost.appendChild(mkCheck(t(lang, "genLower"), lower, (v) => {
          lower = v;
        }));
        optionsHost.appendChild(mkCheck(t(lang, "genUpper"), upper, (v) => {
          upper = v;
        }));
        optionsHost.appendChild(mkCheck(t(lang, "genDigits"), digits, (v) => {
          digits = v;
        }));
        optionsHost.appendChild(mkCheck(t(lang, "genSymbols"), symbols, (v) => {
          symbols = v;
        }));
        optionsHost.appendChild(mkCheck(t(lang, "genNoLookalikes"), excludeLookalikes, (v) => {
          excludeLookalikes = v;
        }));
      } else {
        const wcVal = el("span", { class: "mono" }, String(wordCount));
        const range = el("input", {
          type: "range",
          min: 4,
          max: 10,
          value: wordCount,
          onInput: (e) => {
            wordCount = parseInt(e.target.value, 10);
            wcVal.textContent = String(wordCount);
            regen();
          }
        });
        optionsHost.appendChild(
          el(
            "div",
            { class: "field" },
            el("label", { class: "field-label" }, el("span", null, t(lang, "genWords")), wcVal),
            range
          )
        );
      }
    };
    const tabPwd = el("button", { type: "button", class: "seg-btn is-active" }, t(lang, "genModePassword"));
    const tabPhrase = el("button", { type: "button", class: "seg-btn" }, t(lang, "genModePassphrase"));
    tabPwd.addEventListener("click", () => {
      mode = "password";
      tabPwd.classList.add("is-active");
      tabPhrase.classList.remove("is-active");
      renderOptions();
      regen();
    });
    tabPhrase.addEventListener("click", () => {
      mode = "passphrase";
      tabPhrase.classList.add("is-active");
      tabPwd.classList.remove("is-active");
      renderOptions();
      regen();
    });
    renderOptions();
    regen();
    const content = el(
      "div",
      { class: "settings-group" },
      el("div", { class: "segmented" }, tabPwd, tabPhrase),
      previewNode,
      meterWrap,
      el(
        "div",
        { class: "form-grid-2" },
        el(
          "button",
          { type: "button", class: "btn", onClick: () => {
            triggerHaptic(12);
            regen();
          } },
          svgIcon("refresh", 18),
          t(lang, "generateBtn")
        ),
        el(
          "button",
          {
            type: "button",
            class: "btn",
            onClick: async () => {
              try {
                await session2.clipboard.copySecret(currentValue, session2.settings?.clipboardClearSec ?? 30);
                triggerHaptic();
                showToast(t(lang, "copiedToast"), "success");
              } catch {
                showToast(t(lang, "copiedToast"), "warn");
              }
            }
          },
          svgIcon("copy", 18),
          t(lang, "copyPass")
        )
      ),
      optionsHost,
      onSelect ? el(
        "button",
        {
          type: "button",
          class: "btn btn-primary btn-block",
          onClick: () => {
            onSelect(currentValue);
            sheet.close();
          }
        },
        svgIcon("check", 18),
        t(lang, "genUse")
      ) : null
    );
    const sheet = openBottomSheet({ title: t(lang, "generatorTitle"), content });
    return sheet;
  }

  // src/ui/passwords-view.js
  var SECTION_EMOJIS = ["\u{1F510}", "\u{1F3E6}", "\u{1F4AC}", "\u{1F4BC}", "\u{1F6D2}", "\u{1F3AE}", "\u2601\uFE0F", "\u{1F3E0}", "\u{1F4F1}", "\u2708\uFE0F", "\u{1F3E5}", "\u{1F393}"];
  function renderPasswordsView({
    session: session2,
    lang,
    sections,
    passwords,
    trashedPasswords,
    state,
    onStateChange,
    onRefresh,
    onShowTwoStepBar
  }) {
    const container = el("div", { class: "settings-group view-enter" });
    const copyField = async (value, label) => {
      if (!value) return;
      try {
        const clearSec = session2.settings?.clipboardClearSec ?? 30;
        await session2.clipboard.copySecret(value, clearSec);
        triggerHaptic();
        showToast(`${t(lang, "copiedToast")}: ${label}`, "success");
      } catch (err) {
        showToast(formatError(err, lang), "error");
      }
    };
    const searchInput = el("input", {
      type: "search",
      class: "input",
      value: state.query || "",
      placeholder: t(lang, "searchPlaceholder"),
      autocomplete: "off",
      spellcheck: "false",
      "aria-label": t(lang, "searchPlaceholder"),
      onInput: (e) => {
        onStateChange({ query: e.target.value }, { keepFocus: true });
      }
    });
    const sortSelect = el(
      "select",
      {
        class: "select",
        "aria-label": "Sort",
        onChange: (e) => onStateChange({ sortBy: e.target.value })
      },
      el("option", { value: "updated-desc", selected: state.sortBy === "updated-desc" }, t(lang, "sortUpdated")),
      el("option", { value: "title-asc", selected: state.sortBy === "title-asc" }, t(lang, "sortTitleAsc")),
      el("option", { value: "created-desc", selected: state.sortBy === "created-desc" }, t(lang, "sortCreated")),
      el("option", { value: "favorites-first", selected: state.sortBy === "favorites-first" }, t(lang, "sortFavorites"))
    );
    const genQuickBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-icon",
        "aria-label": t(lang, "generatorTitle"),
        title: t(lang, "generatorTitle"),
        onClick: () => openGeneratorSheet({ session: session2, lang })
      },
      svgIcon("key", 18)
    );
    container.appendChild(
      el(
        "div",
        { class: "toolbar-row" },
        el("div", { class: "search-wrap" }, el("span", { class: "search-icon" }, svgIcon("search", 18)), searchInput),
        genQuickBtn
      )
    );
    const sectionById = new Map(sections.map((s) => [s.id, s]));
    const countBySec = /* @__PURE__ */ new Map();
    for (const p of passwords) {
      const sid = p.data?.sectionId || "uncategorized";
      countBySec.set(sid, (countBySec.get(sid) || 0) + 1);
    }
    const strip = el("div", { class: "section-strip", role: "tablist", "aria-label": t(lang, "manageSections") });
    const addChip = (label, count, active, cls, onClick) => {
      strip.appendChild(
        el(
          "button",
          {
            type: "button",
            role: "tab",
            "aria-selected": active ? "true" : "false",
            class: `sec-chip ${cls || ""} ${active ? "is-active" : ""}`.trim(),
            onClick
          },
          cls ? el("span", { class: "sec-dot" }) : null,
          el("span", null, label),
          count !== null ? el("span", { class: "count-badge" }, String(count)) : null
        )
      );
    };
    addChip(
      t(lang, "allSections"),
      passwords.length,
      !state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && state.sectionId === "all",
      "",
      () => onStateChange({ sectionId: "all", showTrash: false, favoritesOnly: false, duplicatesOnly: false })
    );
    const sortedSections = [...sections].sort((a, b) => (a.data?.order ?? 0) - (b.data?.order ?? 0));
    for (const sec of sortedSections) {
      const d = sec.data || {};
      addChip(
        `${d.emoji || "\u{1F4C1}"} ${d.name || ""}`,
        countBySec.get(sec.id) || 0,
        !state.showTrash && state.sectionId === sec.id,
        accentClassForHex(d.color),
        () => onStateChange({ sectionId: sec.id, showTrash: false, favoritesOnly: false, duplicatesOnly: false })
      );
    }
    const favCount = passwords.filter((p) => p.data?.favorite).length;
    addChip(
      `\u2605 ${t(lang, "favorites")}`,
      favCount,
      !state.showTrash && state.favoritesOnly,
      "",
      () => onStateChange({ sectionId: "all", showTrash: false, favoritesOnly: !state.favoritesOnly, duplicatesOnly: false })
    );
    addChip(
      t(lang, "duplicates"),
      null,
      !state.showTrash && state.duplicatesOnly,
      "",
      () => onStateChange({ sectionId: "all", showTrash: false, favoritesOnly: false, duplicatesOnly: !state.duplicatesOnly })
    );
    addChip(
      `\u{1F5D1} ${t(lang, "trash")}`,
      trashedPasswords.length,
      Boolean(state.showTrash),
      "",
      () => onStateChange({ showTrash: !state.showTrash, favoritesOnly: false, duplicatesOnly: false })
    );
    strip.appendChild(
      el(
        "button",
        {
          type: "button",
          class: "sec-chip",
          onClick: () => openManageSectionsSheet({ session: session2, lang, sections: sortedSections, passwords, onRefresh })
        },
        svgIcon("plus", 15),
        t(lang, "manageSections")
      )
    );
    container.appendChild(strip);
    const selectedIds = state.selectedIds || /* @__PURE__ */ new Set();
    if (selectedIds.size > 0) {
      container.appendChild(
        el(
          "div",
          { class: "multiselect-bar" },
          el("strong", null, `${selectedIds.size} ${t(lang, "multiSelectCount")}`),
          el(
            "div",
            { class: "toolbar-row" },
            el(
              "button",
              {
                type: "button",
                class: "btn btn-sm btn-primary",
                onClick: () => {
                  openBulkMoveSheet({ session: session2, lang, selectedIds, sections: sortedSections, onStateChange, onRefresh });
                }
              },
              svgIcon("link", 14),
              t(lang, "moveToSection")
            ),
            el(
              "button",
              {
                type: "button",
                class: "btn btn-sm btn-danger",
                onClick: async () => {
                  for (const id of selectedIds) {
                    await session2.trashRecord(id);
                  }
                  onStateChange({ selectedIds: /* @__PURE__ */ new Set() });
                  await onRefresh();
                }
              },
              svgIcon("trash", 15),
              t(lang, "moveToTrash")
            ),
            el(
              "button",
              {
                type: "button",
                class: "btn btn-sm",
                onClick: () => onStateChange({ selectedIds: /* @__PURE__ */ new Set() })
              },
              t(lang, "cancelSelection")
            )
          )
        )
      );
    } else {
      container.appendChild(el("div", { class: "toolbar-row" }, sortSelect));
    }
    const sourceList = state.showTrash ? trashedPasswords : passwords;
    const visibleEntries = filterAndSortPasswords(sourceList, {
      query: state.query,
      sectionId: state.showTrash ? "all" : state.sectionId,
      favoritesOnly: !state.showTrash && state.favoritesOnly,
      duplicatesOnly: !state.showTrash && state.duplicatesOnly,
      sortBy: state.sortBy
    });
    if (!state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && state.sectionId !== "all") {
      const activeSec = sectionById.get(state.sectionId);
      if (activeSec) {
        const ad = activeSec.data || {};
        const accentCls = accentClassForHex(ad.color);
        container.appendChild(
          el(
            "div",
            { class: `section-hero-banner ${accentCls}` },
            el(
              "div",
              { class: "section-hero-info" },
              el("span", { class: "section-hero-emoji" }, ad.emoji || "\u{1F4C1}"),
              el(
                "div",
                { class: "section-hero-text" },
                el("h2", null, ad.name || ""),
                el("p", null, `${visibleEntries.length} ${t(lang, "navPasswords")}`)
              )
            ),
            el(
              "button",
              {
                type: "button",
                class: "btn btn-sm btn-primary",
                onClick: () => {
                  openPasswordEditorSheet({
                    session: session2,
                    lang,
                    sections: sortedSections,
                    defaultSectionId: activeSec.id,
                    onSaved: onRefresh
                  });
                }
              },
              svgIcon("plus", 14),
              t(lang, "addEntry")
            )
          )
        );
      }
    }
    const listWrap = el("div", { class: "entry-list", "data-testid": "password-list" });
    if (visibleEntries.length === 0) {
      listWrap.appendChild(
        el(
          "div",
          { class: "glass-card empty-state" },
          svgIcon("lock", 36),
          el("h3", null, t(lang, "emptyPasswords")),
          el("p", null, t(lang, "emptyPasswordsSub"))
        )
      );
      container.appendChild(listWrap);
      return container;
    }
    const isGrouped = state.sectionId === "all" && !state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && !state.query;
    if (isGrouped) {
      const groups = /* @__PURE__ */ new Map();
      const uncategorized = [];
      for (const entry of visibleEntries) {
        const sid = entry.data?.sectionId;
        if (sid && sectionById.has(sid)) {
          if (!groups.has(sid)) groups.set(sid, { section: sectionById.get(sid), entries: [] });
          groups.get(sid).entries.push(entry);
        } else {
          uncategorized.push(entry);
        }
      }
      for (const sec of sortedSections) {
        const g = groups.get(sec.id);
        if (!g || g.entries.length === 0) continue;
        const sd = sec.data || {};
        const accentCls = accentClassForHex(sd.color);
        const toggleArrow = el("span", { class: "count-badge" }, "\u25BC");
        const groupBody = el("div", { class: "section-group-body" });
        for (const entry of g.entries) {
          groupBody.appendChild(
            buildEntryCard({
              entry,
              sectionById,
              selectedIds,
              state,
              session: session2,
              lang,
              sortedSections,
              copyField,
              onStateChange,
              onRefresh,
              onShowTwoStepBar
            })
          );
        }
        const groupWrap = el("div", { class: `section-group ${accentCls}` });
        const groupHeader = el(
          "div",
          {
            class: "section-group-header",
            onClick: () => {
              const isColl = groupWrap.classList.toggle("is-collapsed");
              toggleArrow.textContent = isColl ? "\u25B2" : "\u25BC";
            }
          },
          el(
            "div",
            { class: "section-group-title-wrap" },
            el("span", { class: "section-group-emoji" }, sd.emoji || "\u{1F4C1}"),
            el("span", { class: "section-group-title" }, sd.name || ""),
            el("span", { class: "section-group-badge" }, String(g.entries.length))
          ),
          el("div", { class: "section-group-actions" }, toggleArrow)
        );
        groupWrap.appendChild(groupHeader);
        groupWrap.appendChild(groupBody);
        listWrap.appendChild(groupWrap);
      }
      if (uncategorized.length > 0) {
        const groupBody = el("div", { class: "section-group-body" });
        for (const entry of uncategorized) {
          groupBody.appendChild(
            buildEntryCard({
              entry,
              sectionById,
              selectedIds,
              state,
              session: session2,
              lang,
              sortedSections,
              copyField,
              onStateChange,
              onRefresh,
              onShowTwoStepBar
            })
          );
        }
        const groupWrap = el("div", { class: "section-group" });
        const toggleArrow = el("span", { class: "count-badge" }, "\u25BC");
        const groupHeader = el(
          "div",
          {
            class: "section-group-header",
            onClick: () => {
              const isColl = groupWrap.classList.toggle("is-collapsed");
              toggleArrow.textContent = isColl ? "\u25B2" : "\u25BC";
            }
          },
          el(
            "div",
            { class: "section-group-title-wrap" },
            el("span", { class: "section-group-emoji" }, "\u{1F4C1}"),
            el("span", { class: "section-group-title" }, lang === "en" ? "Uncategorized" : "\u063A\u064A\u0631 \u0645\u0635\u0646\u0651\u0641"),
            el("span", { class: "section-group-badge" }, String(uncategorized.length))
          ),
          el("div", { class: "section-group-actions" }, toggleArrow)
        );
        groupWrap.appendChild(groupHeader);
        groupWrap.appendChild(groupBody);
        listWrap.appendChild(groupWrap);
      }
    } else {
      for (const entry of visibleEntries) {
        listWrap.appendChild(
          buildEntryCard({
            entry,
            sectionById,
            selectedIds,
            state,
            session: session2,
            lang,
            sortedSections,
            copyField,
            onStateChange,
            onRefresh,
            onShowTwoStepBar
          })
        );
      }
    }
    container.appendChild(listWrap);
    return container;
  }
  function buildEntryCard({
    entry,
    sectionById,
    selectedIds,
    state,
    session: session2,
    lang,
    sortedSections,
    copyField,
    onStateChange,
    onRefresh,
    onShowTwoStepBar
  }) {
    const d = entry.data || {};
    const sec = sectionById.get(d.sectionId);
    const accentCls = accentClassForHex(sec?.data?.color);
    const isSelected = selectedIds.has(entry.id);
    const card = el("article", {
      class: `entry-card stagger-item ${accentCls} ${isSelected ? "is-selected" : ""}`.trim(),
      "data-entry-id": entry.id
    });
    let longPressTimer = null;
    card.addEventListener("pointerdown", (e) => {
      if (e.target.closest("button, input, a")) return;
      longPressTimer = setTimeout(() => {
        triggerHaptic(24);
        const next = new Set(selectedIds);
        if (next.has(entry.id)) next.delete(entry.id);
        else next.add(entry.id);
        onStateChange({ selectedIds: next });
      }, 500);
    });
    const cancelLongPress = () => {
      if (longPressTimer) {
        clearTimeout(longPressTimer);
        longPressTimer = null;
      }
    };
    card.addEventListener("pointerup", cancelLongPress);
    card.addEventListener("pointercancel", cancelLongPress);
    card.addEventListener("pointermove", cancelLongPress);
    const favBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-icon btn-ghost",
        "aria-label": `${t(lang, "favorites")} ${d.title}`,
        onClick: async () => {
          await session2.saveRecord({
            id: entry.id,
            type: "password",
            data: { ...d, favorite: !d.favorite },
            createdAt: entry.createdAt
          });
          await onRefresh();
        }
      },
      svgIcon("star", 18, Boolean(d.favorite))
    );
    const topRow = el(
      "div",
      { class: "entry-top" },
      el(
        "div",
        { class: "entry-title-group" },
        el(
          "h3",
          { class: "entry-title" },
          el("span", null, sec?.data?.emoji || "\u{1F510}"),
          el("span", null, d.title || "Untitled")
        ),
        d.url ? el("p", { class: "entry-sub ltr-value" }, d.url) : null
      ),
      !state.showTrash ? favBtn : null
    );
    const fieldsBox = el("div", { class: "entry-fields" });
    if (d.username) {
      fieldsBox.appendChild(
        el(
          "div",
          { class: "secret-field-row" },
          el(
            "div",
            { class: "secret-field-meta" },
            el("span", { class: "secret-field-label" }, t(lang, "usernameLabel")),
            el("span", { class: "secret-field-val ltr-value" }, d.username)
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": `${t(lang, "copyUser")} ${d.title}`,
              onClick: () => copyField(d.username, t(lang, "usernameLabel"))
            },
            svgIcon("copy", 15),
            t(lang, "copyUser")
          )
        )
      );
    }
    if (d.password) {
      const maskedText = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
      const pwdSpan = el("span", { class: "secret-field-val ltr-value" }, maskedText);
      const revealBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-icon btn-sm",
          "aria-label": `${t(lang, "holdToReveal")} ${d.title}`,
          title: t(lang, "holdToReveal")
        },
        svgIcon("eye", 16)
      );
      attachHoldToReveal(revealBtn, {
        onReveal: () => {
          pwdSpan.textContent = d.password;
        },
        onHide: () => {
          pwdSpan.textContent = maskedText;
        },
        autoHideMs: 1e4
      });
      fieldsBox.appendChild(
        el(
          "div",
          { class: "secret-field-row" },
          el(
            "div",
            { class: "secret-field-meta" },
            el("span", { class: "secret-field-label" }, t(lang, "passwordLabel")),
            pwdSpan
          ),
          revealBtn,
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": `${t(lang, "copyPass")} ${d.title}`,
              onClick: () => copyField(d.password, t(lang, "passwordLabel"))
            },
            svgIcon("copy", 15),
            t(lang, "copyPass")
          )
        )
      );
    }
    if (d.url) {
      fieldsBox.appendChild(
        el(
          "div",
          { class: "secret-field-row" },
          el(
            "div",
            { class: "secret-field-meta" },
            el("span", { class: "secret-field-label" }, t(lang, "urlLabel")),
            el("span", { class: "secret-field-val ltr-value" }, d.url)
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": `${t(lang, "copyUrl")} ${d.title}`,
              onClick: () => copyField(d.url, t(lang, "urlLabel"))
            },
            svgIcon("copy", 15)
          )
        )
      );
    }
    if (d.notes) {
      fieldsBox.appendChild(
        el(
          "div",
          { class: "secret-field-row" },
          el(
            "div",
            { class: "secret-field-meta" },
            el("span", { class: "secret-field-label" }, t(lang, "notesLabel")),
            el("span", { class: "secret-field-val" }, d.notes)
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": `${t(lang, "copyNotes")} ${d.title}`,
              onClick: () => copyField(d.notes, t(lang, "notesLabel"))
            },
            svgIcon("copy", 15)
          )
        )
      );
    }
    const actionsRow = el("div", { class: "entry-actions-row" });
    if (state.showTrash) {
      actionsRow.appendChild(
        el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-primary",
            onClick: async () => {
              await session2.restoreRecord(entry.id);
              await onRefresh();
            }
          },
          t(lang, "restore")
        )
      );
      actionsRow.appendChild(
        el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-danger",
            onClick: async () => {
              await session2.permanentlyDeleteRecord(entry.id);
              await onRefresh();
            }
          },
          t(lang, "deleteForever")
        )
      );
    } else {
      if (d.username && d.password) {
        actionsRow.appendChild(
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm btn-dual-copy",
              "aria-label": `${t(lang, "copyBothNow")} ${d.title}`,
              title: t(lang, "copyBothNow"),
              onClick: async () => {
                try {
                  const clearSec = session2.settings?.clipboardClearSec ?? 30;
                  const combined = `${d.username}
${d.password}`;
                  await session2.clipboard.copySecret(combined, clearSec);
                  triggerHaptic();
                  showToast(t(lang, "copiedUserAndPass"), "success");
                } catch (err) {
                  showToast(formatError(err, lang), "error");
                }
              }
            },
            svgIcon("copy", 15),
            t(lang, "copyBothNow")
          )
        );
      }
      actionsRow.appendChild(
        el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-move-sec",
            "aria-label": `${t(lang, "moveToSection")} ${d.title}`,
            title: t(lang, "moveToSection"),
            onClick: () => {
              openMoveEntrySheet({ session: session2, lang, entry, sections: sortedSections, onRefresh });
            }
          },
          svgIcon("link", 14),
          t(lang, "moveToSection")
        )
      );
      actionsRow.appendChild(
        el(
          "button",
          {
            type: "button",
            class: "btn btn-sm",
            "aria-label": `${t(lang, "edit")} ${d.title}`,
            onClick: () => openPasswordEditorSheet({
              session: session2,
              lang,
              sections: sortedSections,
              entry,
              onSaved: onRefresh
            })
          },
          svgIcon("edit", 15),
          t(lang, "edit")
        )
      );
      actionsRow.appendChild(
        el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-danger",
            "aria-label": `${t(lang, "delete")} ${d.title}`,
            onClick: async () => {
              await session2.trashRecord(entry.id);
              showToast(t(lang, "moveToTrash"), "info");
              await onRefresh();
            }
          },
          svgIcon("trash", 15),
          t(lang, "delete")
        )
      );
    }
    card.appendChild(topRow);
    card.appendChild(fieldsBox);
    card.appendChild(actionsRow);
    return card;
  }
  function openMoveEntrySheet({ session: session2, lang, entry, sections, onRefresh }) {
    const currentSecId = entry?.data?.sectionId;
    const list = el("div", { class: "settings-group" });
    for (const s of sections) {
      const isCurrent = s.id === currentSecId;
      const accentCls = accentClassForHex(s.data?.color);
      list.appendChild(
        el(
          "button",
          {
            type: "button",
            class: `btn btn-block ${accentCls} ${isCurrent ? "is-active" : ""}`.trim(),
            disabled: isCurrent,
            onClick: async () => {
              await session2.saveRecord({
                id: entry.id,
                type: "password",
                createdAt: entry.createdAt,
                data: {
                  ...entry.data,
                  sectionId: s.id
                }
              });
              sheet.close();
              triggerHaptic();
              showToast(`${t(lang, "save")} \u2713`, "success");
              await onRefresh();
            }
          },
          el("span", null, s.data?.emoji || "\u{1F4C1}"),
          el("span", null, s.data?.name || ""),
          isCurrent ? el("span", { class: "count-badge" }, "\u2713") : null
        )
      );
    }
    const sheet = openBottomSheet({
      title: t(lang, "moveToSection"),
      content: list
    });
  }
  function openBulkMoveSheet({ session: session2, lang, selectedIds, sections, onStateChange, onRefresh }) {
    const list = el("div", { class: "settings-group" });
    for (const s of sections) {
      const accentCls = accentClassForHex(s.data?.color);
      list.appendChild(
        el(
          "button",
          {
            type: "button",
            class: `btn btn-block ${accentCls}`.trim(),
            onClick: async () => {
              await session2.movePasswordsToSection(selectedIds, s.id);
              sheet.close();
              triggerHaptic();
              onStateChange({ selectedIds: /* @__PURE__ */ new Set() });
              showToast(`${t(lang, "save")} \u2713`, "success");
              await onRefresh();
            }
          },
          el("span", null, s.data?.emoji || "\u{1F4C1}"),
          el("span", null, s.data?.name || "")
        )
      );
    }
    const sheet = openBottomSheet({
      title: `${t(lang, "moveToSection")} (${selectedIds.size})`,
      content: list
    });
  }
  function openPasswordEditorSheet({ session: session2, lang, sections, entry = null, defaultSectionId = null, onSaved }) {
    const d = entry?.data || {};
    const titleInput = el("input", { id: "pe-title", type: "text", class: "input", value: d.title || "", required: true, autocomplete: "off" });
    const secSelect = el(
      "select",
      { id: "pe-section", class: "select" },
      ...sections.map(
        (s) => el(
          "option",
          { value: s.id, selected: (d.sectionId || defaultSectionId || sections[0]?.id) === s.id },
          `${s.data?.emoji || "\u{1F4C1}"} ${s.data?.name || ""}`
        )
      )
    );
    const userInput = el("input", { id: "pe-user", type: "text", class: "input ltr-value", value: d.username || "", autocomplete: "off", spellcheck: "false" });
    const pwdInput = el("input", { id: "pe-pwd", type: "password", class: "input ltr-value", value: d.password || "", autocomplete: "off", spellcheck: "false" });
    const urlInput = el("input", { id: "pe-url", type: "url", class: "input ltr-value", value: d.url || "", placeholder: "https://", autocomplete: "off", spellcheck: "false" });
    const notesInput = el("textarea", { id: "pe-notes", class: "textarea", autocomplete: "off", spellcheck: "false" }, d.notes || "");
    const favCheck = el("input", { type: "checkbox", checked: Boolean(d.favorite) });
    const meterLabel = el("span", { class: "strength-caption" }, "");
    const updateMeter = () => {
      const st = evaluatePasswordStrength(pwdInput.value);
      meterLabel.textContent = pwdInput.value ? `${lang === "en" ? st.labelEn : st.labelAr} (${st.entropyBits} bits)` : "";
    };
    pwdInput.addEventListener("input", updateMeter);
    updateMeter();
    const toggleVisBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-icon",
        "aria-label": t(lang, "holdToReveal"),
        onClick: () => {
          pwdInput.type = pwdInput.type === "password" ? "text" : "password";
        }
      },
      svgIcon("eye", 18)
    );
    const genBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-sm",
        onClick: () => openGeneratorSheet({
          session: session2,
          lang,
          onSelect: (val) => {
            pwdInput.value = val;
            pwdInput.type = "text";
            updateMeter();
          }
        })
      },
      svgIcon("key", 15),
      t(lang, "generateBtn")
    );
    const historyList = Array.isArray(d.passwordHistory) && d.passwordHistory.length > 0 ? el(
      "details",
      { class: "glass-card glass-card-compact" },
      el("summary", null, `${t(lang, "passwordHistory")} (${d.passwordHistory.length})`),
      el(
        "div",
        { class: "entry-fields" },
        ...d.passwordHistory.map(
          (h) => el(
            "div",
            { class: "secret-field-row" },
            el("span", { class: "ltr-value mono" }, h.value),
            el("span", { class: "secret-field-label" }, new Date(h.changedAt).toLocaleDateString(lang === "en" ? "en" : "ar"))
          )
        )
      )
    ) : null;
    const form = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          const title = titleInput.value.trim();
          if (!title) return;
          const nextHistory = Array.isArray(d.passwordHistory) ? [...d.passwordHistory] : [];
          let passwordUpdatedAt = d.passwordUpdatedAt || (/* @__PURE__ */ new Date()).toISOString();
          if (entry && d.password && d.password !== pwdInput.value) {
            nextHistory.unshift({ value: d.password, changedAt: (/* @__PURE__ */ new Date()).toISOString() });
            passwordUpdatedAt = (/* @__PURE__ */ new Date()).toISOString();
          }
          await session2.saveRecord({
            id: entry?.id || null,
            type: "password",
            createdAt: entry?.createdAt,
            data: {
              title,
              sectionId: secSelect.value || null,
              username: userInput.value.trim(),
              password: pwdInput.value,
              url: urlInput.value.trim(),
              notes: notesInput.value,
              favorite: favCheck.checked,
              passwordUpdatedAt,
              passwordHistory: nextHistory.slice(0, 10)
            }
          });
          sheet.close();
          showToast(t(lang, "save"), "success");
          onSaved && await onSaved();
        }
      },
      el("div", { class: "field" }, el("label", { class: "field-label", for: "pe-title" }, t(lang, "titleLabel")), titleInput),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "pe-section" }, t(lang, "sectionLabel")), secSelect),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "pe-user" }, t(lang, "usernameLabel")), userInput),
      el(
        "div",
        { class: "field" },
        el("label", { class: "field-label", for: "pe-pwd" }, el("span", null, t(lang, "passwordLabel")), genBtn),
        el("div", { class: "input-row" }, pwdInput, toggleVisBtn),
        meterLabel
      ),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "pe-url" }, t(lang, "urlLabel")), urlInput),
      el("div", { class: "field" }, el("label", { class: "field-label", for: "pe-notes" }, t(lang, "notesLabel")), notesInput),
      el("label", { class: "checkbox-row" }, favCheck, el("span", null, t(lang, "favorites"))),
      historyList,
      el(
        "div",
        { class: "form-grid-2" },
        el("button", { type: "button", class: "btn", onClick: () => sheet.close() }, t(lang, "cancel")),
        el("button", { type: "submit", class: "btn btn-primary" }, t(lang, "save"))
      )
    );
    const sheet = openBottomSheet({
      title: entry ? t(lang, "editEntry") : t(lang, "addEntry"),
      content: form
    });
  }
  function openManageSectionsSheet({ session: session2, lang, sections, passwords, onRefresh }) {
    const host = el("div", { class: "settings-group" });
    const renderList = () => {
      while (host.firstChild) host.removeChild(host.firstChild);
      const nameIn = el("input", { type: "text", class: "input", placeholder: t(lang, "addSection"), required: true, autocomplete: "off" });
      const emojiSel = el(
        "select",
        { class: "select", "aria-label": "Emoji" },
        ...SECTION_EMOJIS.map((em) => el("option", { value: em }, em))
      );
      const colorSel = el(
        "select",
        { class: "select", "aria-label": "Color" },
        ...SECTION_COLOR_OPTIONS.map((c) => el("option", { value: c.hex }, lang === "en" ? c.nameEn : c.nameAr))
      );
      const addForm = el(
        "form",
        {
          class: "glass-card glass-card-compact settings-group",
          onSubmit: async (e) => {
            e.preventDefault();
            const name = nameIn.value.trim();
            if (!name) return;
            await session2.saveRecord({
              type: "section",
              data: { name, emoji: emojiSel.value, color: colorSel.value, order: sections.length }
            });
            sheet.close();
            await onRefresh();
          }
        },
        nameIn,
        el("div", { class: "form-grid-2" }, emojiSel, colorSel),
        el("button", { type: "submit", class: "btn btn-primary btn-block" }, svgIcon("plus", 16), t(lang, "addSection"))
      );
      host.appendChild(addForm);
      sections.forEach((sec, idx) => {
        const d = sec.data || {};
        const itemCount = passwords.filter((p) => p.data?.sectionId === sec.id).length;
        const renameIn = el("input", { type: "text", class: "input", value: d.name || "", "aria-label": d.name || "Section" });
        const editEmojiSel = el(
          "select",
          { class: "select", "aria-label": "Emoji" },
          ...SECTION_EMOJIS.map((em) => el("option", { value: em, selected: (d.emoji || "\u{1F4C1}") === em }, em))
        );
        const editColorSel = el(
          "select",
          { class: "select", "aria-label": "Color" },
          ...SECTION_COLOR_OPTIONS.map(
            (c) => el("option", { value: c.hex, selected: String(d.color || "#38bdf8").toLowerCase() === c.hex }, lang === "en" ? c.nameEn : c.nameAr)
          )
        );
        const saveBtn = el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-primary",
            onClick: async () => {
              if (!renameIn.value.trim()) return;
              await session2.saveRecord({
                id: sec.id,
                type: "section",
                createdAt: sec.createdAt,
                data: {
                  ...d,
                  name: renameIn.value.trim(),
                  emoji: editEmojiSel.value,
                  color: editColorSel.value
                }
              });
              sheet.close();
              showToast(t(lang, "save"), "success");
              await onRefresh();
            }
          },
          t(lang, "save")
        );
        const moveUpBtn = el(
          "button",
          {
            type: "button",
            class: "btn btn-sm",
            disabled: idx === 0,
            "aria-label": "Move up",
            onClick: async () => {
              const prev = sections[idx - 1];
              await session2.saveRecord({ id: sec.id, type: "section", createdAt: sec.createdAt, data: { ...d, order: idx - 1 } });
              await session2.saveRecord({ id: prev.id, type: "section", createdAt: prev.createdAt, data: { ...prev.data, order: idx } });
              sheet.close();
              await onRefresh();
            }
          },
          "\u2191"
        );
        const delBtn = el(
          "button",
          {
            type: "button",
            class: "btn btn-sm btn-danger",
            disabled: sections.length <= 1,
            onClick: () => {
              sheet.close();
              openDeleteSectionSheet({ session: session2, lang, section: sec, allSections: sections, passwords, onRefresh });
            }
          },
          svgIcon("trash", 14)
        );
        host.appendChild(
          el(
            "div",
            { class: `glass-card glass-card-compact settings-group ${accentClassForHex(d.color)}` },
            el("div", { class: "input-row" }, renameIn, saveBtn),
            el("div", { class: "form-grid-2" }, editEmojiSel, editColorSel),
            el(
              "div",
              { class: "toolbar-row" },
              el("span", { class: "settings-row-desc" }, `${itemCount} ${t(lang, "navPasswords")}`),
              moveUpBtn,
              delBtn
            )
          )
        );
      });
    };
    renderList();
    const sheet = openBottomSheet({ title: t(lang, "manageSections"), content: host });
  }
  function openDeleteSectionSheet({ session: session2, lang, section, allSections, passwords, onRefresh }) {
    const others = allSections.filter((s) => s.id !== section.id);
    const affected = passwords.filter((p) => p.data?.sectionId === section.id);
    const targetSel = el(
      "select",
      { class: "select" },
      ...others.map((s) => el("option", { value: s.id }, `${s.data?.emoji || "\u{1F4C1}"} ${s.data?.name || ""}`))
    );
    const runDelete = async (mode) => {
      const now = (/* @__PURE__ */ new Date()).toISOString();
      const updatedItems = affected.map((p) => ({
        id: p.id,
        type: "password",
        createdAt: p.createdAt,
        deletedAt: mode === "trash" ? now : null,
        data: {
          ...p.data,
          sectionId: mode === "move" ? targetSel.value : p.data.sectionId
        }
      }));
      const encryptedBatch = await session2.encryptBatchForAtomicWrite(updatedItems);
      await session2.storage.atomicOperationWithSnapshot({
        reason: `delete-section-${mode}`,
        putRecords: encryptedBatch,
        deleteIds: [section.id]
      });
      sheet.close();
      showToast(t(lang, "delete"), "info");
      await onRefresh();
    };
    const content = el(
      "div",
      { class: "settings-group" },
      el("p", null, `${section.data?.emoji || "\u{1F4C1}"} ${section.data?.name} (${affected.length})`),
      others.length > 0 ? el("div", { class: "field" }, targetSel) : null,
      others.length > 0 ? el("button", { type: "button", class: "btn btn-primary btn-block", onClick: () => runDelete("move") }, t(lang, "secDeleteMove")) : null,
      el("button", { type: "button", class: "btn btn-danger btn-block", onClick: () => runDelete("trash") }, t(lang, "secDeleteTrash"))
    );
    const sheet = openBottomSheet({ title: t(lang, "secDeleteTitle"), content });
  }

  // src/ui/settings-view.js
  function renderSettingsView({
    session: session2,
    lang,
    storageStatus,
    integrityInfo,
    snapshots,
    pwaState,
    onOpenImportExport,
    onOpenSync,
    onDownloadZip,
    isNativeAndroid = false,
    onRefresh,
    onApplySettings,
    onActivateUpdate,
    onInstallPwa
  }) {
    const container = el("div", { class: "settings-group view-enter" });
    const settings = session2.settings || {};
    const bioState = session2.getBiometricState();
    const langSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "langLabel"),
        onChange: async (e) => {
          await session2.updateSettings({ lang: e.target.value });
          onApplySettings();
        }
      },
      el("option", { value: "ar", selected: lang === "ar" }, "\u0627\u0644\u0639\u0631\u0628\u064A\u0629 (RTL)"),
      el("option", { value: "en", selected: lang === "en" }, "English (LTR)")
    );
    const themeSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "themeLabel"),
        onChange: async (e) => {
          await session2.updateSettings({ theme: e.target.value });
          onApplySettings();
        }
      },
      el("option", { value: "dark", selected: settings.theme === "dark" }, t(lang, "themeDark")),
      el("option", { value: "light", selected: settings.theme === "light" }, t(lang, "themeLight")),
      el("option", { value: "amoled", selected: settings.theme === "amoled" }, t(lang, "themeAmoled"))
    );
    const comboSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "copyComboModeLabel"),
        onChange: async (e) => {
          await session2.updateSettings({ copyComboMode: e.target.value });
          showToast(t(lang, "save"), "success");
        }
      },
      el("option", { value: "two-step", selected: settings.copyComboMode !== "one-tap" }, t(lang, "comboTwoStep")),
      el("option", { value: "one-tap", selected: settings.copyComboMode === "one-tap" }, t(lang, "comboOneTap"))
    );
    container.appendChild(
      el(
        "section",
        { class: "glass-card settings-group" },
        el("h2", { class: "sheet-title" }, t(lang, "settingsAppearance")),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "langLabel")), langSel),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "themeLabel")), themeSel),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "copyComboModeLabel")), comboSel)
      )
    );
    const autoLockSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "autoLockLabel"),
        onChange: async (e) => {
          await session2.updateSettings({ autoLockSec: parseInt(e.target.value, 10) });
          showToast(t(lang, "save"), "success");
        }
      },
      ...[30, 60, 120, 300, 600, 900].map(
        (sec) => el(
          "option",
          { value: sec, selected: (settings.autoLockSec ?? 120) === sec },
          sec < 60 ? `${sec} ${t(lang, "seconds")}` : `${sec / 60} ${t(lang, "minutes")}`
        )
      )
    );
    const bgGraceSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "bgGraceLabel"),
        onChange: async (e) => {
          await session2.updateSettings({ bgGraceSec: parseInt(e.target.value, 10) });
          showToast(t(lang, "save"), "success");
        }
      },
      ...[0, 15, 30, 60].map(
        (sec) => el("option", { value: sec, selected: (settings.bgGraceSec ?? 15) === sec }, `${sec} ${t(lang, "seconds")}`)
      )
    );
    const clipSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "clipboardClearLabel"),
        onChange: async (e) => {
          await session2.updateSettings({ clipboardClearSec: parseInt(e.target.value, 10) });
          showToast(t(lang, "save"), "success");
        }
      },
      ...[0, 15, 30, 60].map(
        (sec) => el("option", { value: sec, selected: (settings.clipboardClearSec ?? 30) === sec }, sec === 0 ? lang === "en" ? "Off" : "\u0645\u0639\u0637\u0651\u0644" : `${sec} ${t(lang, "seconds")}`)
      )
    );
    const reauthCheck = el("input", {
      type: "checkbox",
      checked: settings.reauthSensitive !== false,
      onChange: async (e) => {
        await session2.updateSettings({ reauthSensitive: e.target.checked });
      }
    });
    const wipeSel = el(
      "select",
      {
        class: "select",
        "aria-label": t(lang, "wipeAfterLabel"),
        onChange: async (e) => {
          const val = parseInt(e.target.value, 10);
          if (val > 0) {
            const ok = await requestReauth({ session: session2, lang });
            if (!ok) {
              e.target.value = String(session2.header?.security?.wipeAfterFailures || 0);
              return;
            }
          }
          await session2.setWipeAfterFailures(val);
          showToast(t(lang, "save"), val > 0 ? "warn" : "success");
        }
      },
      el("option", { value: 0, selected: !session2.header?.security?.wipeAfterFailures }, t(lang, "wipeAfterOff")),
      el("option", { value: 5, selected: session2.header?.security?.wipeAfterFailures === 5 }, "5"),
      el("option", { value: 10, selected: session2.header?.security?.wipeAfterFailures === 10 }, "10")
    );
    const bioDesc = bioState.enabled ? bioState.mode === "native" ? lang === "en" ? "Native Android Biometric (Active)" : "\u0628\u0635\u0645\u0629 \u0623\u0646\u062F\u0631\u0648\u064A\u062F \u0627\u0644\u062D\u0642\u064A\u0642\u064A\u0629 (\u0645\u0641\u0639\u0651\u0644\u0629)" : bioState.mode === "prf" ? t(lang, "biometricPrfActive") : t(lang, "biometricConvActive") : t(lang, "biometricOff");
    const bioActionBtn = bioState.enabled ? el(
      "button",
      {
        type: "button",
        class: "btn btn-sm btn-danger",
        onClick: async () => {
          await session2.disableBiometric();
          showToast(t(lang, "disableBiometric"), "info");
          await onRefresh();
        }
      },
      t(lang, "disableBiometric")
    ) : el(
      "button",
      {
        type: "button",
        class: "btn btn-sm btn-primary",
        onClick: () => openBiometricSetupSheet({ session: session2, lang, onDone: onRefresh })
      },
      svgIcon("fingerprint", 16),
      t(lang, "enableBiometric")
    );
    container.appendChild(
      el(
        "section",
        { class: "glass-card settings-group" },
        el("h2", { class: "sheet-title" }, t(lang, "settingsSecurity")),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "autoLockLabel")), autoLockSel),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "bgGraceLabel")), bgGraceSel),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "clipboardClearLabel")), clipSel),
        el("div", { class: "banner banner-info" }, el("span", null, t(lang, "clipboardLimitNote"))),
        el("label", { class: "checkbox-row" }, reauthCheck, el("span", null, t(lang, "reauthLabel"))),
        el(
          "div",
          { class: "settings-row" },
          el("div", { class: "settings-row-info" }, el("div", { class: "settings-row-title" }, t(lang, "biometricTitle")), el("div", { class: "settings-row-desc" }, bioDesc)),
          bioActionBtn
        ),
        el("div", { class: "settings-row" }, el("span", { class: "settings-row-title" }, t(lang, "wipeAfterLabel")), wipeSel),
        el(
          "div",
          { class: "form-grid-2" },
          el(
            "button",
            {
              type: "button",
              class: "btn",
              onClick: () => openChangeMasterPasswordSheet({ session: session2, lang })
            },
            svgIcon("key", 16),
            t(lang, "changeMasterPwd")
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn",
              onClick: () => openRotateRecoverySheet({ session: session2, lang })
            },
            svgIcon("refresh", 16),
            t(lang, "rotateRecoveryKey")
          )
        )
      )
    );
    const healthResultNode = el("div", { class: "banner hidden" });
    const snapList = el("div", { class: "settings-group" });
    if (snapshots.length === 0) {
      snapList.appendChild(el("span", { class: "settings-row-desc" }, lang === "en" ? "No snapshots yet." : "\u0644\u0627 \u062A\u0648\u062C\u062F \u0644\u0642\u0637\u0627\u062A \u0628\u0639\u062F."));
    } else {
      for (const s of snapshots) {
        snapList.appendChild(
          el(
            "div",
            { class: "settings-row" },
            el(
              "div",
              { class: "settings-row-info" },
              el("div", { class: "settings-row-title" }, `${s.reason} (${s.recordCount})`),
              el("div", { class: "settings-row-desc" }, new Date(s.createdAt).toLocaleString(lang === "en" ? "en" : "ar"))
            ),
            el(
              "button",
              {
                type: "button",
                class: "btn btn-sm",
                onClick: async () => {
                  const ok = await requestReauth({ session: session2, lang });
                  if (!ok) return;
                  await session2.storage.restoreSnapshot(s.id);
                  showToast(t(lang, "restoreSnapshot"), "success");
                  await onRefresh();
                }
              },
              t(lang, "restoreSnapshot")
            )
          )
        );
      }
    }
    container.appendChild(
      el(
        "section",
        { class: "glass-card settings-group" },
        el("h2", { class: "sheet-title" }, t(lang, "settingsData")),
        el(
          "button",
          {
            type: "button",
            class: "btn btn-primary btn-block",
            "data-testid": "settings-sync-btn",
            onClick: onOpenSync
          },
          svgIcon("link", 17),
          t(lang, "syncSettingsBtn")
        ),
        el(
          "div",
          { class: "form-grid-2" },
          el("button", { type: "button", class: "btn", onClick: onOpenImportExport }, svgIcon("download", 17), t(lang, "importExportBtn")),
          el(
            "button",
            {
              type: "button",
              class: "btn",
              onClick: async () => {
                const report = await session2.runHealthCheck();
                healthResultNode.className = `banner ${report.ok ? "banner-success" : "banner-danger"}`;
                healthResultNode.textContent = report.ok ? lang === "en" ? `Health Check Passed: ${report.valid}/${report.total} records decrypted & authenticated.` : `\u0646\u062C\u062D \u0627\u0644\u0641\u062D\u0635: \u062A\u0645 \u0641\u0643 \u062A\u0634\u0641\u064A\u0631 \u0648\u0627\u0644\u062A\u062D\u0642\u0642 \u0645\u0646 ${report.valid}/${report.total} \u0633\u062C\u0644 \u0628\u0646\u062C\u0627\u062D \u2713` : lang === "en" ? `Corrupted records detected: ${report.corrupted.length}` : `\u062A\u0645 \u0627\u0643\u062A\u0634\u0627\u0641 ${report.corrupted.length} \u0633\u062C\u0644 \u062A\u0627\u0644\u0641!`;
              }
            },
            svgIcon("shield", 17),
            t(lang, "healthCheckBtn")
          )
        ),
        healthResultNode,
        el("h3", { class: "settings-row-title" }, t(lang, "snapshotsTitle")),
        snapList
      )
    );
    const pwaCard = el("section", { class: "glass-card settings-group" }, el("h2", { class: "sheet-title" }, t(lang, "settingsPwa")));
    if (pwaState.updateWaiting) {
      pwaCard.appendChild(
        el(
          "div",
          { class: "banner banner-info" },
          el("span", null, t(lang, "updateAvailable")),
          el("button", { type: "button", class: "btn btn-sm btn-primary", onClick: onActivateUpdate }, t(lang, "updateConfirmBtn"))
        )
      );
    }
    if (!isNativeAndroid && !pwaState.isInstalled) {
      if (pwaState.canInstall) {
        pwaCard.appendChild(
          el("button", { type: "button", class: "btn btn-primary btn-block", onClick: onInstallPwa }, svgIcon("download", 17), t(lang, "installAppBtn"))
        );
      } else if (pwaState.isIOS) {
        pwaCard.appendChild(el("div", { class: "banner banner-info" }, el("span", null, t(lang, "installIosHint"))));
      }
    }
    if (onDownloadZip) {
      pwaCard.appendChild(
        el(
          "button",
          {
            type: "button",
            class: "btn btn-block",
            "data-testid": "settings-download-zip",
            onClick: onDownloadZip
          },
          svgIcon("download", 17),
          t(lang, "downloadZipBtn")
        )
      );
    }
    const kdfInfo = session2.header ? `${session2.header.kdf} (${JSON.stringify(session2.header.kdfParams)})` : "\u2014";
    pwaCard.appendChild(
      el(
        "div",
        { class: "settings-row" },
        el("span", { class: "settings-row-title" }, t(lang, "storageStatusLabel")),
        el("span", { class: "settings-row-desc" }, storageStatus?.persisted ? t(lang, "storagePersisted") : t(lang, "storageBestEffort"))
      )
    );
    pwaCard.appendChild(
      el(
        "div",
        { class: "settings-row" },
        el("span", { class: "settings-row-title" }, t(lang, "appVersionLabel")),
        el("span", { class: "settings-row-desc ltr-inline mono" }, `v${integrityInfo?.version || "2.2.0"} \u2022 ${kdfInfo}`)
      )
    );
    pwaCard.appendChild(
      el(
        "div",
        { class: "field" },
        el("span", { class: "settings-row-title" }, t(lang, "appShellHashLabel")),
        el("div", { class: "hash-box", "data-testid": "app-shell-hash" }, integrityInfo?.shellSha256 || "computing...")
      )
    );
    if (isNativeAndroid) {
      pwaCard.appendChild(
        el(
          "div",
          { class: "banner banner-success" },
          el(
            "span",
            null,
            lang === "en" ? "Android FLAG_SECURE active: screenshots and screen recording are blocked by the OS." : "\u062D\u0645\u0627\u064A\u0629 \u0627\u0644\u0634\u0627\u0634\u0629 (FLAG_SECURE) \u0645\u0641\u0639\u0651\u0644\u0629 \u0639\u0644\u0649 \u0627\u0644\u0623\u0646\u062F\u0631\u0648\u064A\u062F: \u0644\u0642\u0637\u0627\u062A \u0627\u0644\u0634\u0627\u0634\u0629 \u0648\u0627\u0644\u062A\u0633\u062C\u064A\u0644 \u0645\u062D\u0638\u0648\u0631\u0629 \u0639\u0644\u0649 \u0645\u0633\u062A\u0648\u0649 \u0627\u0644\u0646\u0638\u0627\u0645."
          )
        )
      );
    } else {
      pwaCard.appendChild(el("div", { class: "banner banner-warn" }, el("span", null, t(lang, "screenshotHonesty"))));
    }
    pwaCard.appendChild(
      el(
        "button",
        {
          type: "button",
          class: "btn btn-danger btn-block",
          onClick: () => openWipeVaultSheet({ session: session2, lang })
        },
        svgIcon("trash", 17),
        t(lang, "wipeVaultBtn")
      )
    );
    container.appendChild(pwaCard);
    return container;
  }
  function openBiometricSetupSheet({ session: session2, lang, onDone }) {
    const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
    const pwdIn = el("input", {
      type: "password",
      class: "input ltr-value",
      autocomplete: "off",
      spellcheck: "false",
      required: true,
      placeholder: t(lang, "masterPasswordLabel")
    });
    const body = el("div", { class: "settings-group" });
    const submitBtn = el("button", { type: "submit", class: "btn btn-primary btn-block" }, svgIcon("fingerprint", 18), t(lang, "enableBiometric"));
    const form = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          errBox.classList.add("hidden");
          submitBtn.disabled = true;
          try {
            const res = await session2.enrollBiometricWithPassword(pwdIn.value);
            pwdIn.value = "";
            if (res.mode === "prf" || res.mode === "native") {
              sheet.close();
              showToast(
                res.mode === "native" ? lang === "en" ? "Native Android Biometric Enabled \u2713" : "\u062A\u0645 \u062A\u0641\u0639\u064A\u0644 \u0628\u0635\u0645\u0629 \u0623\u0646\u062F\u0631\u0648\u064A\u062F \u0628\u0646\u062C\u0627\u062D \u2713" : t(lang, "biometricPrfActive"),
                "success"
              );
              onDone && await onDone();
            } else if (res.mode === "prf-unavailable") {
              while (body.firstChild) body.removeChild(body.firstChild);
              body.appendChild(el("div", { class: "banner banner-warn" }, el("span", null, lang === "en" ? res.warningEn : res.warningAr)));
              body.appendChild(
                el(
                  "div",
                  { class: "form-grid-2" },
                  el("button", { type: "button", class: "btn", onClick: () => sheet.close() }, t(lang, "cancel")),
                  el(
                    "button",
                    {
                      type: "button",
                      class: "btn btn-primary",
                      onClick: async () => {
                        await res._armConvenience();
                        sheet.close();
                        showToast(t(lang, "biometricConvActive"), "warn", 4200);
                        onDone && await onDone();
                      }
                    },
                    lang === "en" ? "Enable Convenience Mode" : "\u062A\u0641\u0639\u064A\u0644 \u0648\u0636\u0639 \u0627\u0644\u0631\u0627\u062D\u0629"
                  )
                )
              );
            }
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove("hidden");
            submitBtn.disabled = false;
          }
        }
      },
      errBox,
      el("div", { class: "field" }, el("label", { class: "field-label" }, t(lang, "masterPasswordLabel")), pwdIn),
      submitBtn
    );
    body.appendChild(form);
    const sheet = openBottomSheet({ title: t(lang, "biometricTitle"), content: body });
  }
  function openChangeMasterPasswordSheet({ session: session2, lang }) {
    const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
    const curIn = el("input", { type: "password", class: "input ltr-value", autocomplete: "off", required: true });
    const newIn = el("input", { type: "password", class: "input ltr-value", autocomplete: "off", required: true, minlength: 12 });
    const confIn = el("input", { type: "password", class: "input ltr-value", autocomplete: "off", required: true });
    const submitBtn = el("button", { type: "submit", class: "btn btn-primary btn-block" }, t(lang, "save"));
    const form = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          errBox.classList.add("hidden");
          if (newIn.value !== confIn.value) {
            errBox.textContent = t(lang, "passwordsMismatch");
            errBox.classList.remove("hidden");
            return;
          }
          submitBtn.disabled = true;
          try {
            await session2.changeMasterPassword({
              currentPassword: curIn.value,
              newMasterPassword: newIn.value
            });
            curIn.value = "";
            newIn.value = "";
            confIn.value = "";
            sheet.close();
            showToast(t(lang, "changeMasterPwd"), "success");
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove("hidden");
            submitBtn.disabled = false;
          }
        }
      },
      errBox,
      el("div", { class: "field" }, el("label", { class: "field-label" }, lang === "en" ? "Current Master Password" : "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0627\u0644\u062D\u0627\u0644\u064A\u0629"), curIn),
      el("div", { class: "field" }, el("label", { class: "field-label" }, lang === "en" ? "New Master Password (12+ chars)" : "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0627\u0644\u062C\u062F\u064A\u062F\u0629 (\u0661\u0662 \u062D\u0631\u0641\u0627\u064B+)"), newIn),
      el("div", { class: "field" }, el("label", { class: "field-label" }, t(lang, "confirmPasswordLabel")), confIn),
      submitBtn
    );
    const sheet = openBottomSheet({ title: t(lang, "changeMasterPwd"), content: form });
  }
  function openRotateRecoverySheet({ session: session2, lang }) {
    const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
    const pwdIn = el("input", { type: "password", class: "input ltr-value", autocomplete: "off", required: true });
    const host = el("div", { class: "settings-group" });
    const form = el(
      "form",
      {
        onSubmit: async (e) => {
          e.preventDefault();
          errBox.classList.add("hidden");
          try {
            const { recoveryKeyFormatted } = await session2.rotateRecoveryKeyWithPassword(pwdIn.value);
            pwdIn.value = "";
            while (host.firstChild) host.removeChild(host.firstChild);
            host.appendChild(el("div", { class: "banner banner-warn" }, el("span", null, t(lang, "recoveryModalWarn"))));
            host.appendChild(el("div", { class: "recovery-key-display" }, recoveryKeyFormatted));
            host.appendChild(
              el(
                "button",
                {
                  type: "button",
                  class: "btn btn-primary btn-block",
                  onClick: async () => {
                    try {
                      await session2.clipboard.copySecret(recoveryKeyFormatted, 0);
                      showToast(t(lang, "copiedToast"), "success");
                    } catch (err) {
                      showToast(formatError(err, lang), "warn");
                    }
                  }
                },
                svgIcon("copy", 16),
                t(lang, "copyRecoveryKey")
              )
            );
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove("hidden");
          }
        }
      },
      errBox,
      el("div", { class: "field" }, el("label", { class: "field-label" }, t(lang, "masterPasswordLabel")), pwdIn),
      el("button", { type: "submit", class: "btn btn-primary btn-block" }, t(lang, "rotateRecoveryKey"))
    );
    host.appendChild(form);
    openBottomSheet({ title: t(lang, "rotateRecoveryKey"), content: host });
  }
  function openWipeVaultSheet({ session: session2, lang }) {
    const confirmIn = el("input", {
      type: "text",
      class: "input ltr-value",
      autocomplete: "off",
      placeholder: "WIPE"
    });
    const btn = el(
      "button",
      {
        type: "button",
        class: "btn btn-danger btn-block",
        disabled: true,
        onClick: async () => {
          const ok = await requestReauth({ session: session2, lang });
          if (!ok) return;
          await session2.wipeVault();
          sheet.close();
          showToast(t(lang, "wipeVaultBtn"), "warn");
        }
      },
      t(lang, "wipeVaultBtn")
    );
    confirmIn.addEventListener("input", () => {
      btn.disabled = confirmIn.value.trim().toUpperCase() !== "WIPE";
    });
    const content = el(
      "div",
      { class: "settings-group" },
      el("div", { class: "banner banner-danger" }, el("span", null, t(lang, "wipeVaultWarn"))),
      el("div", { class: "field" }, el("label", { class: "field-label" }, lang === "en" ? "Type WIPE to confirm" : "\u0627\u0643\u062A\u0628 WIPE \u0644\u0644\u062A\u0623\u0643\u064A\u062F"), confirmIn),
      btn
    );
    const sheet = openBottomSheet({ title: t(lang, "wipeVaultBtn"), content });
  }

  // src/domain/audit.js
  var OLD_PASSWORD_DAYS = 180;
  function computeVaultAuditAndStats({
    sections = [],
    passwords = [],
    cards = [],
    notes = [],
    now = Date.now()
  }) {
    const weak = [];
    const reusedMap = /* @__PURE__ */ new Map();
    const old = [];
    const oldCutoffMs = now - OLD_PASSWORD_DAYS * 24 * 60 * 60 * 1e3;
    for (const entry of passwords) {
      const d = entry.data || {};
      const pwd = String(d.password || "");
      const strength = evaluatePasswordStrength(pwd);
      if (strength.score <= 1) {
        weak.push({ entry, strength });
      }
      if (pwd.length > 0) {
        const bucket = reusedMap.get(pwd) || [];
        bucket.push(entry);
        reusedMap.set(pwd, bucket);
      }
      const changedAt = Date.parse(d.passwordUpdatedAt || entry.updatedAt || entry.createdAt || "");
      if (!Number.isNaN(changedAt) && changedAt < oldCutoffMs) {
        const ageDays = Math.floor((now - changedAt) / (24 * 60 * 60 * 1e3));
        old.push({ entry, ageDays });
      }
    }
    const reusedGroups = [];
    const reusedEntryIds = /* @__PURE__ */ new Set();
    for (const list of reusedMap.values()) {
      if (list.length > 1) {
        reusedGroups.push(list);
        for (const e of list) reusedEntryIds.add(e.id);
      }
    }
    const sectionCounts = /* @__PURE__ */ new Map();
    for (const sec of sections) {
      sectionCounts.set(sec.id, {
        id: sec.id,
        name: sec.data?.name || "",
        emoji: sec.data?.emoji || "\u{1F4C1}",
        color: sec.data?.color || "#38bdf8",
        count: 0
      });
    }
    let uncategorizedCount = 0;
    for (const entry of passwords) {
      const sid = entry.data?.sectionId;
      if (sid && sectionCounts.has(sid)) {
        sectionCounts.get(sid).count += 1;
      } else {
        uncategorizedCount += 1;
      }
    }
    const bySection = Array.from(sectionCounts.values()).sort((a, b) => b.count - a.count);
    if (uncategorizedCount > 0) {
      bySection.push({
        id: "uncategorized",
        name: "\u063A\u064A\u0631 \u0645\u0635\u0646\u0651\u0641",
        nameEn: "Uncategorized",
        emoji: "\u{1F4C2}",
        color: "#94a3b8",
        count: uncategorizedCount
      });
    }
    const totalPwd = passwords.length;
    let healthScore = 100;
    if (totalPwd > 0) {
      const weakPenalty = weak.length / totalPwd * 50;
      const reusedPenalty = reusedEntryIds.size / totalPwd * 35;
      const oldPenalty = old.length / totalPwd * 15;
      healthScore = Math.max(0, Math.round(100 - weakPenalty - reusedPenalty - oldPenalty));
    }
    return {
      totals: {
        passwords: passwords.length,
        cards: cards.length,
        notes: notes.length,
        sections: sections.length,
        all: passwords.length + cards.length + notes.length
      },
      bySection,
      audit: {
        healthScore,
        weak,
        reusedGroups,
        reusedCount: reusedEntryIds.size,
        old
      }
    };
  }

  // src/ui/stats-view.js
  function formatBytes(bytes) {
    if (!bytes || bytes < 1024) return `${bytes || 0} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  function renderStatsView({
    session: session2,
    lang,
    sections,
    passwords,
    cards,
    notes,
    vaultSizeBytes = 0,
    onOpenSection,
    onOpenBackup
  }) {
    const container = el("div", { class: "settings-group view-enter" });
    const stats = computeVaultAuditAndStats({ sections, passwords, cards, notes });
    const lastBackup = session2.settings?.lastBackupAt;
    const daysSinceBackup = lastBackup ? Math.floor((Date.now() - Date.parse(lastBackup)) / (24 * 60 * 60 * 1e3)) : Infinity;
    if (daysSinceBackup >= (session2.settings?.backupReminderDays ?? 7) && stats.totals.all > 0) {
      container.appendChild(
        el(
          "div",
          { class: "banner banner-warn" },
          el("span", null, t(lang, "backupReminderBanner")),
          el("button", { type: "button", class: "btn btn-sm btn-primary", onClick: onOpenBackup }, t(lang, "tabExport"))
        )
      );
    }
    const mkKpi = (label, value, suffix = "") => {
      const numNode = el("span", { class: "kpi-num ltr-inline" }, "0");
      animateCounter(numNode, value);
      return el(
        "div",
        { class: "kpi-box stagger-item" },
        el("div", null, numNode, suffix ? el("span", { class: "kpi-label" }, suffix) : null),
        el("span", { class: "kpi-label" }, label)
      );
    };
    container.appendChild(
      el(
        "section",
        { class: "stats-kpi-grid", "aria-label": t(lang, "statsTitle") },
        mkKpi(t(lang, "totalPasswords"), stats.totals.passwords),
        mkKpi(t(lang, "totalCards"), stats.totals.cards),
        mkKpi(t(lang, "totalNotes"), stats.totals.notes),
        mkKpi(t(lang, "securityScore"), stats.audit.healthScore, "%")
      )
    );
    const radius = 74;
    const circumference = 2 * Math.PI * radius;
    const donutSvg = svgEl("svg", {
      class: "donut-svg",
      viewBox: "0 0 200 200",
      role: "img",
      "aria-label": t(lang, "bySectionTitle")
    });
    donutSvg.appendChild(
      svgEl("circle", {
        cx: 100,
        cy: 100,
        r: radius,
        fill: "none",
        stroke: "rgba(148, 163, 184, 0.16)",
        "stroke-width": 24
      })
    );
    const totalPwd = stats.totals.passwords;
    let offset = 0;
    if (totalPwd > 0) {
      for (const item of stats.bySection) {
        if (item.count === 0) continue;
        const fraction = item.count / totalPwd;
        const segLen = Math.max(2, fraction * circumference);
        const circle = svgEl("circle", {
          class: "donut-slice",
          cx: 100,
          cy: 100,
          r: radius,
          fill: "none",
          stroke: item.color || "#38bdf8",
          "stroke-width": 24,
          "stroke-dasharray": `${segLen} ${circumference}`,
          "stroke-dashoffset": String(-offset),
          tabindex: "0",
          role: "button",
          "aria-label": `${item.name}: ${item.count}`
        });
        circle.addEventListener("click", () => {
          if (item.id !== "uncategorized") onOpenSection(item.id);
        });
        donutSvg.appendChild(circle);
        offset += segLen;
      }
    }
    const barsWrap = el("div", { class: "section-bars" });
    const maxCount = Math.max(1, ...stats.bySection.map((s) => s.count));
    for (const item of stats.bySection) {
      const pct = Math.round(item.count / maxCount * 100);
      const barSvg = svgEl(
        "svg",
        { class: "section-bar-svg", viewBox: "0 0 100 8", preserveAspectRatio: "none", "aria-hidden": "true" },
        svgEl("rect", { x: 0, y: 0, width: 100, height: 8, rx: 4, fill: "rgba(148,163,184,0.18)" }),
        svgEl("rect", { x: 0, y: 0, width: pct, height: 8, rx: 4, fill: item.color || "#38bdf8" })
      );
      const secBtn = el(
        "button",
        {
          type: "button",
          class: "section-bar-btn",
          onClick: () => {
            if (item.id !== "uncategorized") onOpenSection(item.id);
          }
        },
        el(
          "div",
          { class: "section-bar-top" },
          el("span", null, `${item.emoji} ${lang === "en" && item.nameEn ? item.nameEn : item.name}`),
          el("span", { class: "mono" }, String(item.count))
        ),
        barSvg
      );
      barsWrap.appendChild(secBtn);
    }
    container.appendChild(
      el(
        "section",
        { class: "glass-card settings-group" },
        el("div", null, el("h2", { class: "sheet-title" }, t(lang, "bySectionTitle")), el("p", { class: "settings-row-desc" }, t(lang, "bySectionHint"))),
        el(
          "div",
          { class: "stats-charts-grid" },
          el(
            "div",
            { class: "donut-wrap" },
            donutSvg,
            el(
              "div",
              { class: "donut-center" },
              el("strong", { class: "kpi-num" }, String(totalPwd)),
              el("span", { class: "kpi-label" }, t(lang, "totalPasswords"))
            )
          ),
          barsWrap
        )
      )
    );
    const mkAuditBox = (title, count, cls, items) => {
      return el(
        "div",
        { class: `glass-card glass-card-compact settings-group ${cls}` },
        el("div", { class: "section-bar-top" }, el("span", null, title), el("strong", { class: "mono" }, String(count))),
        items.length > 0 ? el(
          "div",
          { class: "settings-row-desc" },
          items.slice(0, 4).map((x) => x.data?.title || x.entry?.data?.title || "").filter(Boolean).join(" \u2022 ")
        ) : el("span", { class: "settings-row-desc" }, lang === "en" ? "All clear \u2713" : "\u0645\u0645\u062A\u0627\u0632 \u2713")
      );
    };
    container.appendChild(
      el(
        "section",
        { class: "glass-card settings-group" },
        el("h2", { class: "sheet-title" }, t(lang, "securityScore")),
        el("p", { class: "settings-row-desc" }, t(lang, "auditOfflineNote")),
        el(
          "div",
          { class: "audit-grid" },
          mkAuditBox(t(lang, "auditWeak"), stats.audit.weak.length, stats.audit.weak.length ? "banner-danger" : "banner-success", stats.audit.weak),
          mkAuditBox(t(lang, "auditReused"), stats.audit.reusedCount, stats.audit.reusedCount ? "banner-warn" : "banner-success", stats.audit.reusedGroups.flat()),
          mkAuditBox(t(lang, "auditOld"), stats.audit.old.length, stats.audit.old.length ? "banner-warn" : "banner-success", stats.audit.old)
        )
      )
    );
    const lastBackupText = lastBackup ? new Date(lastBackup).toLocaleString(lang === "en" ? "en" : "ar") : t(lang, "neverBackedUp");
    container.appendChild(
      el(
        "section",
        { class: "glass-card" },
        el(
          "div",
          { class: "settings-row" },
          el("span", { class: "settings-row-title" }, t(lang, "lastBackupLabel")),
          el("span", { class: "settings-row-desc" }, lastBackupText)
        ),
        el(
          "div",
          { class: "settings-row" },
          el("span", { class: "settings-row-title" }, t(lang, "vaultSizeLabel")),
          el("span", { class: "settings-row-desc ltr-inline mono" }, formatBytes(vaultSizeBytes))
        )
      )
    );
    return container;
  }

  // src/ui/sync-sheet.js
  function openSyncSheet({
    session: session2,
    lang,
    sections,
    passwords,
    cards,
    notes,
    initialTab = "send",
    initialSyncCode = "",
    onSynced
  }) {
    let activeTab = initialSyncCode ? "receive" : initialTab;
    const root = el("div", { class: "settings-group" });
    const body = el("div", { class: "settings-group" });
    const tabSend = el(
      "button",
      {
        type: "button",
        class: `seg-btn ${activeTab === "send" ? "is-active" : ""}`.trim(),
        onClick: () => {
          activeTab = "send";
          renderBody();
        }
      },
      t(lang, "syncTabSend")
    );
    const tabRecv = el(
      "button",
      {
        type: "button",
        class: `seg-btn ${activeTab === "receive" ? "is-active" : ""}`.trim(),
        onClick: () => {
          activeTab = "receive";
          renderBody();
        }
      },
      t(lang, "syncTabReceive")
    );
    root.append(el("div", { class: "segmented" }, tabSend, tabRecv), body);
    const renderSend = () => {
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const outWrap = el("div", { class: "settings-group hidden" });
      const lastSyncAt = session2.settings?.lastSyncAt || null;
      const scopeSel = el(
        "select",
        { class: "select", "aria-label": t(lang, "syncScopeLabel") },
        el("option", { value: "delta", selected: Boolean(lastSyncAt) }, t(lang, "syncScopeDelta")),
        el("option", { value: "full", selected: !lastSyncAt }, t(lang, "syncScopeFull"))
      );
      const passIn = el("input", {
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: t(lang, "syncPassPlaceholder"),
        "data-testid": "sync-send-pass"
      });
      const toggleEye = el(
        "button",
        {
          type: "button",
          class: "btn btn-icon",
          "aria-label": t(lang, "holdToReveal"),
          onClick: () => {
            passIn.type = passIn.type === "password" ? "text" : "password";
          }
        },
        svgIcon("eye", 18)
      );
      const genPassBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-sm",
          onClick: () => {
            passIn.value = generatePassword({ length: 14, lower: true, upper: true, digits: true, symbols: false, excludeLookalikes: true });
            passIn.type = "text";
            triggerHaptic();
          }
        },
        svgIcon("key", 15),
        t(lang, "syncGenPassBtn")
      );
      const createBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-primary btn-block",
          "data-testid": "sync-generate-btn",
          onClick: async () => {
            errBox.classList.add("hidden");
            const scope = scopeSel.value;
            const payload = selectSyncRecords({
              sections,
              passwords,
              cards,
              notes,
              mode: scope,
              sinceIso: scope === "delta" ? lastSyncAt : null
            });
            const totalItems = payload.passwords.length + payload.cards.length + payload.notes.length;
            if (totalItems === 0 && payload.sections.length === 0) {
              errBox.textContent = t(lang, "syncNothingToSend");
              errBox.classList.remove("hidden");
              return;
            }
            createBtn.disabled = true;
            try {
              const encoded = await encodeSyncPackage({
                payload,
                passphrase: passIn.value
              });
              const isWebHost = (window.location.protocol === "https:" || window.location.protocol === "http:") && window.location.origin !== "null" && !window.Capacitor?.isNativePlatform?.();
              const baseUrl = isWebHost ? `${window.location.origin}${window.location.pathname}` : "";
              const linkInfo = isWebHost ? buildSyncLink(baseUrl, encoded.token) : { fitsUrl: false, url: "" };
              await session2.updateSettings({ lastSyncAt: (/* @__PURE__ */ new Date()).toISOString() });
              clearNode(outWrap);
              outWrap.classList.remove("hidden");
              const kb = (encoded.byteLength / 1024).toFixed(1);
              outWrap.appendChild(
                el(
                  "div",
                  { class: "banner banner-success" },
                  el(
                    "span",
                    null,
                    `${t(lang, "syncReadySummary")}: ${encoded.counts.passwords} \u{1F511} \u2022 ${encoded.counts.cards} \u{1F4B3} \u2022 ${encoded.counts.notes} \u{1F4DD} (${kb} KB)`
                  )
                )
              );
              if (isWebHost && linkInfo.fitsUrl) {
                const linkArea = el("textarea", {
                  class: "textarea ltr-value mono",
                  readonly: true,
                  rows: 3,
                  value: linkInfo.url,
                  "data-testid": "sync-output-link"
                });
                const shareOrCopyRow = el(
                  "div",
                  { class: "form-grid-2" },
                  el(
                    "button",
                    {
                      type: "button",
                      class: "btn btn-primary",
                      "data-testid": "sync-copy-link",
                      onClick: async () => {
                        try {
                          await session2.clipboard.copySecret(linkInfo.url, 0);
                          triggerHaptic();
                          showToast(t(lang, "syncLinkCopied"), "success");
                        } catch {
                          linkArea.select();
                          showToast(t(lang, "syncCopyManual"), "warn");
                        }
                      }
                    },
                    svgIcon("link", 16),
                    t(lang, "syncCopyLinkBtn")
                  ),
                  typeof navigator.share === "function" ? el(
                    "button",
                    {
                      type: "button",
                      class: "btn",
                      onClick: async () => {
                        try {
                          await navigator.share({
                            title: t(lang, "appName"),
                            text: t(lang, "syncShareText"),
                            url: linkInfo.url
                          });
                        } catch {
                        }
                      }
                    },
                    svgIcon("share", 16),
                    t(lang, "syncShareLinkBtn")
                  ) : el(
                    "button",
                    {
                      type: "button",
                      class: "btn",
                      "data-testid": "sync-copy-code",
                      onClick: async () => {
                        try {
                          await session2.clipboard.copySecret(encoded.code, 0);
                          triggerHaptic();
                          showToast(t(lang, "syncCodeCopied"), "success");
                        } catch {
                          showToast(t(lang, "syncCopyManual"), "warn");
                        }
                      }
                    },
                    svgIcon("copy", 16),
                    t(lang, "syncCopyCodeBtn")
                  )
                );
                outWrap.appendChild(
                  el(
                    "div",
                    { class: "field" },
                    el("label", { class: "field-label" }, t(lang, "syncOneTapLinkLabel")),
                    linkArea
                  )
                );
                outWrap.appendChild(shareOrCopyRow);
              } else if (isWebHost) {
                outWrap.appendChild(
                  el("div", { class: "banner banner-warn" }, el("span", null, t(lang, "syncTooLargeForLink")))
                );
              }
              const codeArea = el("textarea", {
                class: "textarea ltr-value mono",
                readonly: true,
                rows: 2,
                value: encoded.code,
                "data-testid": "sync-output-code"
              });
              outWrap.appendChild(
                el(
                  "div",
                  { class: "field" },
                  el("label", { class: "field-label" }, t(lang, "syncCodeLabel")),
                  codeArea,
                  el(
                    "button",
                    {
                      type: "button",
                      class: "btn btn-sm",
                      onClick: async () => {
                        try {
                          await session2.clipboard.copySecret(encoded.code, 0);
                          triggerHaptic();
                          showToast(t(lang, "syncCodeCopied"), "success");
                        } catch {
                          codeArea.select();
                          showToast(t(lang, "syncCopyManual"), "warn");
                        }
                      }
                    },
                    svgIcon("copy", 15),
                    t(lang, "syncCopyCodeBtn")
                  )
                )
              );
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove("hidden");
            } finally {
              createBtn.disabled = false;
            }
          }
        },
        svgIcon("link", 17),
        t(lang, "syncGenerateBtn")
      );
      body.appendChild(
        el("div", { class: "banner banner-info" }, el("span", null, t(lang, "syncSecurityNote")))
      );
      body.appendChild(errBox);
      body.appendChild(
        el(
          "div",
          { class: "field" },
          el("label", { class: "field-label" }, t(lang, "syncScopeLabel")),
          scopeSel
        )
      );
      body.appendChild(
        el(
          "div",
          { class: "field" },
          el("div", { class: "field-label" }, el("span", null, t(lang, "syncPassLabel")), genPassBtn),
          el("div", { class: "input-row" }, passIn, toggleEye)
        )
      );
      body.appendChild(createBtn);
      body.appendChild(outWrap);
    };
    const renderReceive = () => {
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const previewWrap = el("div", { class: "settings-group hidden" });
      const codeIn = el("textarea", {
        class: "textarea ltr-value mono",
        rows: 3,
        autocomplete: "off",
        spellcheck: "false",
        value: initialSyncCode || "",
        placeholder: t(lang, "syncReceivePlaceholder"),
        "data-testid": "sync-recv-input"
      });
      const passIn = el("input", {
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        placeholder: t(lang, "syncPassPlaceholder"),
        "data-testid": "sync-recv-pass"
      });
      const stratSel = el(
        "select",
        { class: "select", "aria-label": t(lang, "syncStrategyLabel") },
        el("option", { value: "smart", selected: true }, t(lang, "syncStrategySmart")),
        el("option", { value: "add-only" }, t(lang, "syncStrategyAddOnly"))
      );
      const previewBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-primary btn-block",
          "data-testid": "sync-preview-btn",
          onClick: async () => {
            errBox.classList.add("hidden");
            clearNode(previewWrap);
            previewWrap.classList.add("hidden");
            previewBtn.disabled = true;
            try {
              const incoming = await decodeSyncPackage({
                input: codeIn.value,
                passphrase: passIn.value
              });
              const plan = planSyncMerge({
                incoming,
                localSections: sections,
                localPasswords: passwords,
                localCards: cards,
                localNotes: notes,
                strategy: stratSel.value
              });
              previewWrap.classList.remove("hidden");
              const s = plan.summary;
              previewWrap.appendChild(
                el(
                  "div",
                  { class: "banner banner-info", "data-testid": "sync-diff-summary" },
                  el(
                    "span",
                    null,
                    `${t(lang, "syncPreviewDiff")}: +${s.added} ${t(lang, "syncAddedLabel")} \u2022 ${s.updated} ${t(lang, "syncUpdatedLabel")} \u2022 ${s.unchanged} ${t(lang, "syncUnchangedLabel")}`
                  )
                )
              );
              const applyBtn = el(
                "button",
                {
                  type: "button",
                  class: "btn btn-primary btn-block",
                  "data-testid": "sync-apply-btn",
                  onClick: async () => {
                    applyBtn.disabled = true;
                    try {
                      const res = await applySyncMerge({ session: session2, plan });
                      triggerHaptic();
                      showToast(
                        `${t(lang, "syncSuccessToast")} (+${res.summary.added} / \u21BB${res.summary.updated})`,
                        "success",
                        4e3
                      );
                      sheet.close();
                      if (onSynced) await onSynced();
                    } catch (err) {
                      errBox.textContent = formatError(err, lang);
                      errBox.classList.remove("hidden");
                      applyBtn.disabled = false;
                    }
                  }
                },
                svgIcon("check", 17),
                t(lang, "syncApplyBtn")
              );
              previewWrap.appendChild(applyBtn);
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove("hidden");
            } finally {
              previewBtn.disabled = false;
            }
          }
        },
        svgIcon("refresh", 17),
        t(lang, "syncPreviewBtn")
      );
      if (initialSyncCode) {
        body.appendChild(
          el("div", { class: "banner banner-success" }, el("span", null, t(lang, "syncAutofilledBanner")))
        );
      }
      body.appendChild(errBox);
      body.appendChild(
        el(
          "div",
          { class: "field" },
          el("label", { class: "field-label" }, t(lang, "syncReceiveCodeLabel")),
          codeIn
        )
      );
      body.appendChild(
        el(
          "div",
          { class: "field" },
          el("label", { class: "field-label" }, t(lang, "syncPassLabel")),
          passIn
        )
      );
      body.appendChild(
        el(
          "div",
          { class: "field" },
          el("label", { class: "field-label" }, t(lang, "syncStrategyLabel")),
          stratSel
        )
      );
      body.appendChild(previewBtn);
      body.appendChild(previewWrap);
    };
    const renderBody = () => {
      tabSend.classList.toggle("is-active", activeTab === "send");
      tabRecv.classList.toggle("is-active", activeTab === "receive");
      clearNode(body);
      if (activeTab === "send") renderSend();
      else renderReceive();
    };
    renderBody();
    const sheet = openBottomSheet({ title: t(lang, "syncTitle"), content: root });
    return sheet;
  }

  // src/ui/unlock-view.js
  function createStrengthMeter(lang) {
    const bars = el(
      "div",
      { class: "strength-bars", "aria-hidden": "true" },
      el("div", { class: "strength-bar" }),
      el("div", { class: "strength-bar" }),
      el("div", { class: "strength-bar" }),
      el("div", { class: "strength-bar" })
    );
    const labelNode = el("span", null, "");
    const bitsNode = el("span", { class: "ltr-inline mono" }, "");
    const wrap = el(
      "div",
      { class: "strength-meter" },
      bars,
      el("div", { class: "strength-caption" }, labelNode, bitsNode)
    );
    const update = (pwd) => {
      if (!pwd) {
        wrap.className = "strength-meter";
        labelNode.textContent = "";
        bitsNode.textContent = "";
        return;
      }
      const res = evaluatePasswordStrength(pwd);
      wrap.className = `strength-meter strength-${res.score}`;
      labelNode.textContent = lang === "en" ? `${res.labelEn} \u2014 ${res.feedbackEn}` : `${res.labelAr} \u2014 ${res.feedbackAr}`;
      bitsNode.textContent = `${res.entropyBits} bits`;
    };
    return { wrap, update };
  }
  function renderUnlockView({
    session: session2,
    lang,
    onToggleLang,
    onDownloadZip = null,
    hasPendingSync = false,
    pendingRecoveryKey = null,
    onRecoveryConfirmed = null
  }) {
    const screen = el("main", { class: "auth-screen view-enter" });
    const langBtn = el(
      "button",
      {
        type: "button",
        class: "btn btn-sm",
        "aria-label": t(lang, "langLabel"),
        onClick: onToggleLang
      },
      lang === "ar" ? "English" : "\u0627\u0644\u0639\u0631\u0628\u064A\u0629"
    );
    const zipBtn = onDownloadZip ? el(
      "button",
      {
        type: "button",
        class: "btn btn-sm",
        "aria-label": t(lang, "downloadZipBtn"),
        title: t(lang, "downloadZipBtn"),
        "data-testid": "auth-download-zip",
        onClick: onDownloadZip
      },
      svgIcon("download", 15),
      t(lang, "downloadZipShort")
    ) : null;
    const topTools = el("div", { class: "toolbar-row" }, langBtn, zipBtn);
    if (pendingRecoveryKey) {
      const savedCheckbox = el("input", { type: "checkbox", id: "recovery-saved-check" });
      const enterBtn = el(
        "button",
        {
          type: "button",
          class: "btn btn-primary btn-block",
          disabled: true,
          onClick: () => onRecoveryConfirmed && onRecoveryConfirmed()
        },
        t(lang, "enterVaultBtn")
      );
      savedCheckbox.addEventListener("change", () => {
        enterBtn.disabled = !savedCheckbox.checked;
      });
      const card2 = el(
        "section",
        { class: "glass-card auth-card recovery-print-box" },
        el(
          "div",
          { class: "auth-hero" },
          el("div", { class: "auth-hero-icon" }, svgIcon("key", 30)),
          el("h1", null, t(lang, "recoveryModalTitle")),
          el("p", null, t(lang, "recoveryModalWarn"))
        ),
        el("div", { class: "recovery-key-display", "data-testid": "recovery-key-box" }, pendingRecoveryKey),
        el(
          "div",
          { class: "form-grid-2 no-print" },
          el(
            "button",
            {
              type: "button",
              class: "btn",
              onClick: async () => {
                try {
                  await session2.clipboard.copySecret(pendingRecoveryKey, 0);
                  triggerHaptic();
                  showToast(t(lang, "copiedToast"), "success");
                } catch {
                  showToast(t(lang, "copyRecoveryKey"), "warn");
                }
              }
            },
            svgIcon("copy", 18),
            t(lang, "copyRecoveryKey")
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn",
              onClick: () => window.print()
            },
            t(lang, "printRecoveryKey")
          )
        ),
        el(
          "label",
          { class: "checkbox-row no-print", for: "recovery-saved-check" },
          savedCheckbox,
          el("span", null, t(lang, "recoverySavedCheckbox"))
        ),
        enterBtn
      );
      screen.appendChild(card2);
      return screen;
    }
    if (!session2.hasVault) {
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const pwdInput = el("input", {
        id: "create-master-pwd",
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        minlength: MIN_MASTER_PASSWORD_LEN,
        required: true
      });
      const confirmInput = el("input", {
        id: "confirm-master-pwd",
        type: "password",
        class: "input ltr-value",
        autocomplete: "off",
        spellcheck: "false",
        required: true
      });
      const meter = createStrengthMeter(lang);
      pwdInput.addEventListener("input", () => meter.update(pwdInput.value));
      const toggleEye = el(
        "button",
        {
          type: "button",
          class: "btn btn-icon",
          "aria-label": t(lang, "holdToReveal"),
          onClick: () => {
            const next = pwdInput.type === "password" ? "text" : "password";
            pwdInput.type = next;
            confirmInput.type = next;
          }
        },
        svgIcon("eye", 18)
      );
      const submitBtn = el("button", { type: "submit", class: "btn btn-primary btn-block" }, t(lang, "createVaultBtn"));
      const form = el(
        "form",
        {
          onSubmit: async (e) => {
            e.preventDefault();
            errBox.classList.add("hidden");
            const pwd = pwdInput.value;
            const conf = confirmInput.value;
            if (Array.from(pwd).length < MIN_MASTER_PASSWORD_LEN) {
              errBox.textContent = lang === "en" ? `Master password must be at least ${MIN_MASTER_PASSWORD_LEN} characters.` : `\u064A\u062C\u0628 \u0623\u0644\u0627 \u062A\u0642\u0644 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0639\u0646 ${MIN_MASTER_PASSWORD_LEN} \u062D\u0631\u0641\u0627\u064B.`;
              errBox.classList.remove("hidden");
              return;
            }
            if (pwd !== conf) {
              errBox.textContent = t(lang, "passwordsMismatch");
              errBox.classList.remove("hidden");
              return;
            }
            submitBtn.disabled = true;
            submitBtn.textContent = t(lang, "calibratingKdf");
            try {
              const res = await session2.createVault({ masterPassword: pwd });
              pwdInput.value = "";
              confirmInput.value = "";
              onRecoveryConfirmed && onRecoveryConfirmed(res.recoveryKeyFormatted);
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove("hidden");
              submitBtn.disabled = false;
              submitBtn.textContent = t(lang, "createVaultBtn");
            }
          }
        },
        errBox,
        el(
          "div",
          { class: "field" },
          el("label", { class: "field-label", for: "create-master-pwd" }, t(lang, "masterPasswordLabel")),
          el("div", { class: "input-row" }, pwdInput, toggleEye),
          meter.wrap
        ),
        el(
          "div",
          { class: "field" },
          el("label", { class: "field-label", for: "confirm-master-pwd" }, t(lang, "confirmPasswordLabel")),
          confirmInput
        ),
        el("div", { class: "banner banner-info" }, el("span", null, t(lang, "noHintNote"))),
        el("div", { class: "field" }),
        submitBtn
      );
      const card2 = el(
        "section",
        { class: "glass-card auth-card" },
        topTools,
        el(
          "div",
          { class: "auth-hero" },
          el("div", { class: "auth-hero-icon" }, svgIcon("shield", 32)),
          el("h1", null, t(lang, "createVaultTitle")),
          el("p", null, t(lang, "createVaultSubtitle"))
        ),
        hasPendingSync ? el("div", { class: "banner banner-info", "data-testid": "pending-sync-banner" }, el("span", null, t(lang, "syncPendingUnlockBanner"))) : null,
        form
      );
      screen.appendChild(card2);
      return screen;
    }
    let mode = "password";
    const card = el("section", { class: "glass-card auth-card" });
    const renderUnlockCard = () => {
      while (card.firstChild) card.removeChild(card.firstChild);
      const errBox = el("div", { class: "banner banner-danger hidden", role: "alert" });
      const bioState = session2.getBiometricState();
      const lockoutMs = session2.getLockoutRemainingMs();
      if (lockoutMs > 0) {
        const secs = Math.ceil(lockoutMs / 1e3);
        errBox.textContent = lang === "en" ? `Too many failed attempts. Try again in ${secs}s.` : `\u0645\u062D\u0627\u0648\u0644\u0627\u062A \u0641\u0627\u0634\u0644\u0629 \u0645\u062A\u0643\u0631\u0631\u0629. \u062D\u0627\u0648\u0644 \u0645\u062C\u062F\u062F\u0627\u064B \u0628\u0639\u062F ${secs} \u062B\u0627\u0646\u064A\u0629.`;
        errBox.classList.remove("hidden");
      }
      card.appendChild(topTools);
      card.appendChild(
        el(
          "div",
          { class: "auth-hero" },
          el("div", { class: "auth-hero-icon" }, svgIcon("lock", 30)),
          el("h1", null, t(lang, "lockedTitle")),
          el("p", null, t(lang, "lockedSubtitle"))
        )
      );
      if (hasPendingSync) {
        card.appendChild(
          el("div", { class: "banner banner-info", "data-testid": "pending-sync-banner" }, el("span", null, t(lang, "syncPendingUnlockBanner")))
        );
      }
      card.appendChild(errBox);
      if (mode === "password") {
        const pwdInput = el("input", {
          id: "unlock-master-pwd",
          type: "password",
          class: "input ltr-value",
          autocomplete: "off",
          spellcheck: "false",
          required: true,
          placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
        });
        const submitBtn = el("button", { type: "submit", class: "btn btn-primary btn-block" }, t(lang, "unlockBtn"));
        const form = el(
          "form",
          {
            onSubmit: async (e) => {
              e.preventDefault();
              errBox.classList.add("hidden");
              submitBtn.disabled = true;
              submitBtn.textContent = t(lang, "unlocking");
              try {
                await session2.unlockWithPassword(pwdInput.value);
                pwdInput.value = "";
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove("hidden");
                submitBtn.disabled = false;
                submitBtn.textContent = t(lang, "unlockBtn");
              }
            }
          },
          el(
            "div",
            { class: "field" },
            el("label", { class: "field-label", for: "unlock-master-pwd" }, t(lang, "masterPasswordLabel")),
            pwdInput
          ),
          submitBtn
        );
        card.appendChild(form);
        if (bioState.enabled) {
          const isNative = bioState.mode === "native";
          const bioLabel = isNative ? lang === "en" ? "Unlock with Fingerprint" : "\u0641\u062A\u062D \u0628\u0628\u0635\u0645\u0629 \u0627\u0644\u0625\u0635\u0628\u0639" : t(lang, "unlockWithFingerprint");
          const bioBtn = el(
            "button",
            {
              type: "button",
              class: `btn btn-block ${isNative ? "btn-primary" : ""}`.trim(),
              disabled: !bioState.ready,
              onClick: async () => {
                errBox.classList.add("hidden");
                try {
                  await session2.unlockWithBiometric();
                } catch (err) {
                  errBox.textContent = formatError(err, lang);
                  errBox.classList.remove("hidden");
                }
              }
            },
            svgIcon("fingerprint", 20),
            bioLabel
          );
          card.appendChild(bioBtn);
          if (bioState.mode === "convenience" && !bioState.ready) {
            card.appendChild(
              el(
                "div",
                { class: "banner banner-warn" },
                el(
                  "span",
                  null,
                  lang === "en" ? "Convenience biometric mode requires Master Password after cold start or 24h." : "\u0648\u0636\u0639 \u0627\u0644\u0628\u0635\u0645\u0629 \u0627\u0644\u0633\u0631\u064A\u0639 \u064A\u062A\u0637\u0644\u0628 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0631\u0626\u064A\u0633\u064A\u0629 \u0628\u0639\u062F \u0625\u0639\u0627\u062F\u0629 \u0627\u0644\u062A\u0634\u063A\u064A\u0644 \u0623\u0648 \u0643\u0644 \u0662\u0664 \u0633\u0627\u0639\u0629."
                )
              )
            );
          }
        }
        card.appendChild(
          el(
            "button",
            {
              type: "button",
              class: "btn btn-ghost btn-block",
              onClick: () => {
                mode = "recovery";
                renderUnlockCard();
              }
            },
            svgIcon("key", 18),
            t(lang, "useRecoveryKey")
          )
        );
      } else {
        const recInput = el("textarea", {
          id: "unlock-recovery-key",
          class: "textarea ltr-value",
          autocomplete: "off",
          spellcheck: "false",
          placeholder: "XXXX-XXXX-XXXX-...",
          required: true
        });
        const newPwdInput = el("input", {
          id: "recovery-new-master",
          type: "password",
          class: "input ltr-value",
          autocomplete: "off",
          spellcheck: "false",
          placeholder: t(lang, "newMasterOptional")
        });
        const submitBtn = el("button", { type: "submit", class: "btn btn-primary btn-block" }, t(lang, "unlockBtn"));
        const form = el(
          "form",
          {
            onSubmit: async (e) => {
              e.preventDefault();
              errBox.classList.add("hidden");
              submitBtn.disabled = true;
              submitBtn.textContent = t(lang, "unlocking");
              try {
                const nextMaster = newPwdInput.value.trim() || null;
                await session2.unlockWithRecoveryKey(recInput.value, nextMaster);
                recInput.value = "";
                newPwdInput.value = "";
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove("hidden");
                submitBtn.disabled = false;
                submitBtn.textContent = t(lang, "unlockBtn");
              }
            }
          },
          el(
            "div",
            { class: "field" },
            el("label", { class: "field-label", for: "unlock-recovery-key" }, t(lang, "recoveryInputLabel")),
            recInput
          ),
          el(
            "div",
            { class: "field" },
            el("label", { class: "field-label", for: "recovery-new-master" }, t(lang, "newMasterOptional")),
            newPwdInput
          ),
          submitBtn
        );
        card.appendChild(form);
        card.appendChild(
          el(
            "button",
            {
              type: "button",
              class: "btn btn-ghost btn-block",
              onClick: () => {
                mode = "password";
                renderUnlockCard();
              }
            },
            t(lang, "backToPassword")
          )
        );
      }
    };
    renderUnlockCard();
    screen.appendChild(card);
    return screen;
  }

  // src/main.js
  var APP_VERSION = "2.2.0";
  function isCapacitorAndroid() {
    return typeof window !== "undefined" && typeof window.Capacitor !== "undefined" && window.Capacitor?.isNativePlatform?.() === true && window.Capacitor?.getPlatform?.() === "android";
  }
  function isStandaloneFile() {
    return typeof window !== "undefined" && window.location?.protocol === "file:";
  }
  function isChromeExtension() {
    return typeof window !== "undefined" && window.location?.protocol === "chrome-extension:";
  }
  function canDownloadZip() {
    return !isCapacitorAndroid() && !isStandaloneFile() && !isChromeExtension();
  }
  var storage = new VaultStorage();
  var session = new VaultSession({ storage });
  var appState = {
    tab: "passwords",
    // passwords | cards | notes | stats | settings
    pendingRecoveryKey: null,
    sections: [],
    passwords: [],
    trashedPasswords: [],
    cards: [],
    notes: [],
    snapshots: [],
    vaultSizeBytes: 0,
    storageStatus: { persisted: false, usageBytes: 0, quotaBytes: 0, percentUsed: 0 },
    integrityInfo: { version: APP_VERSION, shellSha256: "" },
    pwFilter: {
      query: "",
      sectionId: "all",
      favoritesOnly: false,
      duplicatesOnly: false,
      showTrash: false,
      sortBy: "updated-desc",
      selectedIds: /* @__PURE__ */ new Set()
    },
    notesQuery: "",
    twoStepCopy: null,
    // { title, password }
    isOnline: typeof navigator !== "undefined" ? navigator.onLine : true,
    pwa: {
      deferredPrompt: null,
      canInstall: false,
      isInstalled: window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true,
      isIOS: /iphone|ipad|ipod/i.test(navigator.userAgent || ""),
      updateWaiting: null
    },
    sharedImportText: "",
    pendingSyncCode: "",
    isOverlayMode: false
  };
  function getLang() {
    return session.settings?.lang === "en" ? "en" : "ar";
  }
  function applyThemeAndDirection() {
    const settings = session.settings || {};
    const lang = getLang();
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "en" ? "ltr" : "rtl";
    document.documentElement.dataset.theme = settings.theme || "dark";
    const lowEnd = navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2 || navigator.deviceMemory && navigator.deviceMemory <= 2;
    if (settings.lowEndBlur === "reduced" || settings.lowEndBlur === "auto" && lowEnd) {
      document.documentElement.dataset.blur = "reduced";
    } else {
      delete document.documentElement.dataset.blur;
    }
    const themeColorMeta = document.querySelector('meta[name="theme-color"]');
    if (themeColorMeta) {
      const color = settings.theme === "light" ? "#eef3fb" : settings.theme === "amoled" ? "#000000" : "#070b14";
      themeColorMeta.setAttribute("content", color);
    }
    const pTitle = document.getElementById("privacy-title");
    const pSub = document.getElementById("privacy-sub");
    if (pTitle) pTitle.textContent = t(lang, "privacyOverlayTitle");
    if (pSub) pSub.textContent = t(lang, "privacyOverlaySub");
  }
  async function computeRuntimeIntegrity() {
    if (isStandaloneFile() || isChromeExtension()) {
      appState.integrityInfo = {
        version: APP_VERSION,
        shellSha256: isChromeExtension() ? "chrome-extension-local" : "standalone-offline-local"
      };
      return;
    }
    try {
      const resp = await fetch("./app-integrity.json", { cache: "no-store" });
      if (resp.ok) {
        const json = await resp.json();
        if (json?.shellSha256) {
          appState.integrityInfo = {
            version: json.version || APP_VERSION,
            shellSha256: json.shellSha256
          };
          return;
        }
      }
    } catch {
    }
    try {
      const files = ["./index.html", "./styles/theme.css", "./styles/components.css", "./manifest.webmanifest"];
      const parts = [];
      for (const f of files) {
        const r = await fetch(f, { cache: "no-store" });
        if (r.ok) parts.push(await r.text());
      }
      const hash = await sha256Hex(parts.join("\n"));
      appState.integrityInfo = { version: APP_VERSION, shellSha256: hash };
    } catch {
      appState.integrityInfo = { version: APP_VERSION, shellSha256: "offline-local" };
    }
  }
  async function loadDecryptedVaultData() {
    if (!session.isUnlocked) return;
    const [sections, allPasswords, cards, notes, snapshots, allRaw] = await Promise.all([
      session.listRecords("section"),
      session.listRecords("password", { includeTrashed: true }),
      session.listRecords("card"),
      session.listRecords("note"),
      storage.listSnapshots(),
      storage.getAllRecords()
    ]);
    appState.sections = sections.sort((a, b) => (a.data?.order ?? 0) - (b.data?.order ?? 0));
    appState.passwords = allPasswords.filter((p) => !p.deletedAt);
    appState.trashedPasswords = allPasswords.filter((p) => Boolean(p.deletedAt));
    appState.cards = cards;
    appState.notes = notes;
    appState.snapshots = snapshots;
    let bytes = JSON.stringify(session.header || {}).length;
    for (const r of allRaw) bytes += JSON.stringify(r).length;
    appState.vaultSizeBytes = bytes;
  }
  function withViewTransition(fn) {
    const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduced && typeof document.startViewTransition === "function") {
      document.startViewTransition(fn);
    } else {
      fn();
    }
  }
  function renderApp({ preserveSearchFocus = false } = {}) {
    const root = document.getElementById("app");
    if (!root) return;
    const lang = getLang();
    let activeSearchPos = null;
    if (preserveSearchFocus && document.activeElement?.type === "search") {
      activeSearchPos = document.activeElement.selectionStart;
    }
    clearNode(root);
    if (!session.isUnlocked || appState.pendingRecoveryKey) {
      root.appendChild(
        renderUnlockView({
          session,
          lang,
          pendingRecoveryKey: appState.pendingRecoveryKey,
          hasPendingSync: Boolean(appState.pendingSyncCode),
          onToggleLang: async () => {
            await session.updateSettings({ lang: lang === "ar" ? "en" : "ar" });
            applyThemeAndDirection();
            renderApp();
          },
          onRecoveryConfirmed: async (newRecoveryKey) => {
            if (typeof newRecoveryKey === "string") {
              appState.pendingRecoveryKey = newRecoveryKey;
              renderApp();
            } else {
              appState.pendingRecoveryKey = null;
              await loadDecryptedVaultData();
              withViewTransition(() => renderApp());
            }
          },
          // Hide ZIP download in native Android, standalone file://, and Chrome Extension
          onDownloadZip: canDownloadZip() ? handleDownloadZip : null
        })
      );
      return;
    }
    const header = el(
      "header",
      { class: "app-header" },
      el(
        "div",
        { class: "header-inner" },
        el(
          "div",
          { class: "brand-mark" },
          el("div", { class: "brand-logo", "aria-hidden": "true" }, svgIcon("shield", 18)),
          el("h1", { class: "brand-title" }, t(lang, "appName"))
        ),
        el(
          "div",
          { class: "header-actions" },
          // In Chrome Extension popup, offer quick expand to full browser tab
          isChromeExtension() && document.documentElement.classList.contains("chrome-popup-mode") && typeof chrome !== "undefined" && chrome.tabs ? el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": lang === "en" ? "Open Full Tab" : "\u0641\u062A\u062D \u0643\u0627\u0645\u0644",
              title: lang === "en" ? "Open Full Tab" : "\u0641\u062A\u062D \u0641\u064A \u062A\u0628\u0648\u064A\u0628 \u0643\u0627\u0645\u0644",
              onClick: () => chrome.tabs.create({ url: chrome.runtime.getURL("app.html") })
            },
            "\u2197"
          ) : null,
          // Install button moved to Settings view only
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": t(lang, "syncTitle"),
              "data-testid": "header-sync-btn",
              onClick: () => openDeviceSync("send")
            },
            svgIcon("link", 15),
            t(lang, "syncBtnShort")
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm",
              "aria-label": t(lang, "lockNow"),
              onClick: () => {
                appState.twoStepCopy = null;
                session.lock({ reason: "manual" });
              }
            },
            svgIcon("lock", 16),
            t(lang, "lockNow")
          )
        )
      )
    );
    const mainShell = el("main", { class: "app-shell" });
    if (!appState.isOnline) {
      mainShell.appendChild(el("div", { class: "banner banner-info" }, el("span", null, t(lang, "offlineBadge"))));
    }
    if (appState.pwa.updateWaiting) {
      mainShell.appendChild(
        el(
          "div",
          { class: "banner banner-info" },
          el("span", null, t(lang, "updateAvailable")),
          el("button", { type: "button", class: "btn btn-sm btn-primary", onClick: activateWaitingUpdate }, t(lang, "updateConfirmBtn"))
        )
      );
    }
    if (appState.tab === "passwords") {
      mainShell.appendChild(
        renderPasswordsView({
          session,
          lang,
          sections: appState.sections,
          passwords: appState.passwords,
          trashedPasswords: appState.trashedPasswords,
          state: appState.pwFilter,
          onStateChange: (patch, opts = {}) => {
            appState.pwFilter = { ...appState.pwFilter, ...patch };
            renderApp({ preserveSearchFocus: Boolean(opts.keepFocus) });
          },
          onRefresh: refreshAndRender,
          onShowTwoStepBar: (info) => {
            appState.twoStepCopy = info;
            renderApp();
          }
        })
      );
    } else if (appState.tab === "cards") {
      mainShell.appendChild(
        renderCardsView({
          session,
          lang,
          cards: appState.cards,
          onRefresh: refreshAndRender
        })
      );
    } else if (appState.tab === "notes") {
      mainShell.appendChild(
        renderNotesView({
          session,
          lang,
          notes: appState.notes,
          query: appState.notesQuery,
          onQueryChange: (q) => {
            appState.notesQuery = q;
            renderApp({ preserveSearchFocus: true });
          },
          onRefresh: refreshAndRender
        })
      );
    } else if (appState.tab === "stats") {
      mainShell.appendChild(
        renderStatsView({
          session,
          lang,
          sections: appState.sections,
          passwords: appState.passwords,
          cards: appState.cards,
          notes: appState.notes,
          vaultSizeBytes: appState.vaultSizeBytes,
          onOpenSection: (sectionId) => {
            appState.pwFilter = {
              ...appState.pwFilter,
              sectionId,
              showTrash: false,
              favoritesOnly: false,
              duplicatesOnly: false
            };
            appState.tab = "passwords";
            withViewTransition(() => renderApp());
          },
          onOpenBackup: () => openImportExportSheet({
            session,
            lang,
            sections: appState.sections,
            passwords: appState.passwords,
            cards: appState.cards,
            notes: appState.notes,
            initialTab: "export",
            onChanged: refreshAndRender
          })
        })
      );
    } else if (appState.tab === "settings") {
      mainShell.appendChild(
        renderSettingsView({
          session,
          lang,
          storageStatus: appState.storageStatus,
          integrityInfo: appState.integrityInfo,
          snapshots: appState.snapshots,
          pwaState: appState.pwa,
          onOpenImportExport: () => openImportExportSheet({
            session,
            lang,
            sections: appState.sections,
            passwords: appState.passwords,
            cards: appState.cards,
            notes: appState.notes,
            initialTab: "import",
            onChanged: refreshAndRender
          }),
          onOpenSync: () => openDeviceSync("send"),
          onDownloadZip: canDownloadZip() ? handleDownloadZip : null,
          isNativeAndroid: isCapacitorAndroid(),
          onRefresh: refreshAndRender,
          onApplySettings: () => {
            applyThemeAndDirection();
            renderApp();
          },
          onActivateUpdate: activateWaitingUpdate,
          onInstallPwa: handleInstallPwa
        })
      );
    }
    let miniBar = null;
    if (appState.twoStepCopy) {
      const { title, password } = appState.twoStepCopy;
      miniBar = el(
        "div",
        { class: "mini-copy-bar", role: "region", "aria-label": t(lang, "copyCombo") },
        el("span", null, `${title}: ${t(lang, "twoStepNextPass")}`),
        el(
          "div",
          { class: "toolbar-row" },
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm btn-primary",
              onClick: async () => {
                await session.clipboard.copySecret(password, session.settings?.clipboardClearSec ?? 30);
                triggerHaptic();
                showToast(`${t(lang, "copiedToast")}: ${t(lang, "passwordLabel")}`, "success");
                appState.twoStepCopy = null;
                renderApp();
              }
            },
            svgIcon("copy", 15),
            t(lang, "copyPassNow")
          ),
          el(
            "button",
            {
              type: "button",
              class: "btn btn-icon btn-sm btn-ghost",
              "aria-label": t(lang, "close"),
              onClick: () => {
                appState.twoStepCopy = null;
                renderApp();
              }
            },
            svgIcon("close", 16)
          )
        )
      );
    }
    let fab = null;
    if (appState.tab === "passwords" || appState.tab === "cards" || appState.tab === "notes") {
      const fabLabel = appState.tab === "passwords" ? t(lang, "addEntry") : appState.tab === "cards" ? t(lang, "addCard") : t(lang, "addNote");
      fab = el(
        "button",
        {
          type: "button",
          class: "fab-btn",
          "aria-label": fabLabel,
          title: fabLabel,
          onClick: () => {
            triggerHaptic(14);
            if (appState.tab === "passwords") {
              openPasswordEditorSheet({
                session,
                lang,
                sections: appState.sections,
                defaultSectionId: appState.pwFilter.sectionId !== "all" ? appState.pwFilter.sectionId : null,
                onSaved: refreshAndRender
              });
            } else if (appState.tab === "cards") {
              openCardEditorSheet({ session, lang, onSaved: refreshAndRender });
            } else {
              openNoteEditorSheet({ session, lang, onSaved: refreshAndRender });
            }
          }
        },
        svgIcon("plus", 24)
      );
    }
    const navItems = [
      { id: "passwords", icon: "key", label: t(lang, "navPasswords") },
      { id: "cards", icon: "card", label: t(lang, "navCards") },
      { id: "notes", icon: "note", label: t(lang, "navNotes") },
      { id: "stats", icon: "chart", label: t(lang, "navStats") },
      { id: "settings", icon: "settings", label: t(lang, "navSettings") }
    ];
    const bottomNav = el(
      "nav",
      { class: "bottom-nav", "aria-label": "Navigation" },
      el(
        "div",
        { class: "bottom-nav-inner" },
        ...navItems.map(
          (item) => el(
            "button",
            {
              type: "button",
              class: `nav-item ${appState.tab === item.id ? "is-active" : ""}`.trim(),
              "aria-current": appState.tab === item.id ? "page" : void 0,
              onClick: () => {
                if (appState.tab === item.id) return;
                appState.tab = item.id;
                appState.twoStepCopy = null;
                withViewTransition(() => renderApp());
              }
            },
            svgIcon(item.icon, 20),
            el("span", null, item.label)
          )
        )
      )
    );
    let overlayBar = null;
    if (appState.isOverlayMode) {
      overlayBar = el(
        "div",
        { class: "overlay-pin-bar" },
        el("span", null, "\u{1F4CC} " + (lang === "en" ? "Khazna Quick Overlay" : "\u062E\u0632\u0646\u0629 \u2014 \u0627\u062E\u062A\u0635\u0627\u0631 \u0627\u0644\u0648\u0635\u0648\u0644 \u0627\u0644\u0633\u0631\u064A\u0639 \u0641\u0648\u0642 \u0627\u0644\u0634\u0627\u0634\u0629")),
        el(
          "div",
          { class: "toolbar-row" },
          el(
            "button",
            {
              type: "button",
              class: "btn btn-sm btn-ghost",
              onClick: () => {
                appState.isOverlayMode = false;
                document.documentElement.classList.remove("overlay-mode");
                renderApp();
              }
            },
            "\u2715"
          )
        )
      );
    }
    if (overlayBar) root.appendChild(overlayBar);
    root.appendChild(header);
    root.appendChild(mainShell);
    if (miniBar) root.appendChild(miniBar);
    if (fab) root.appendChild(fab);
    root.appendChild(bottomNav);
    if (preserveSearchFocus) {
      const searchEl = root.querySelector('input[type="search"]');
      if (searchEl) {
        searchEl.focus();
        if (activeSearchPos !== null) {
          try {
            searchEl.setSelectionRange(activeSearchPos, activeSearchPos);
          } catch {
          }
        }
      }
    }
    if (appState.pendingSyncCode) {
      const code = appState.pendingSyncCode;
      appState.pendingSyncCode = "";
      openDeviceSync("receive", code);
    }
    if (appState.sharedImportText) {
      const shared = appState.sharedImportText;
      appState.sharedImportText = "";
      openImportExportSheet({
        session,
        lang,
        sections: appState.sections,
        passwords: appState.passwords,
        cards: appState.cards,
        notes: appState.notes,
        initialTab: "import",
        initialPastedText: shared,
        onChanged: refreshAndRender
      });
    }
  }
  async function refreshAndRender() {
    await loadDecryptedVaultData();
    renderApp();
  }
  function openDeviceSync(initialTab = "send", initialSyncCode = "") {
    openSyncSheet({
      session,
      lang: getLang(),
      sections: appState.sections,
      passwords: appState.passwords,
      cards: appState.cards,
      notes: appState.notes,
      initialTab,
      initialSyncCode,
      onSynced: refreshAndRender
    });
  }
  async function handleDownloadZip() {
    const lang = getLang();
    try {
      const resp = await fetch("./khazna-pwa.zip", { cache: "no-store" });
      if (!resp.ok) throw new Error("ZIP unavailable");
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "khazna-pwa.zip";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4e3);
      showToast(t(lang, "downloadZipToast"), "success");
    } catch {
      showToast(lang === "en" ? "Could not download khazna-pwa.zip" : "\u062A\u0639\u0630\u0651\u0631 \u062A\u0646\u0632\u064A\u0644 \u0645\u0644\u0641 khazna-pwa.zip", "error");
    }
  }
  function captureIncomingSyncHash() {
    const hash = window.location.hash || "";
    if (!hash || !hash.includes("sync=")) return false;
    const token = extractSyncTokenFromInput(hash);
    if (!token) return false;
    appState.pendingSyncCode = `${SYNC_PREFIX}${token}`;
    try {
      window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`);
    } catch {
    }
    return true;
  }
  async function handleInstallPwa() {
    const promptEvt = appState.pwa.deferredPrompt;
    if (!promptEvt) return;
    await promptEvt.prompt();
    const choice = await promptEvt.userChoice;
    if (choice?.outcome === "accepted") {
      appState.pwa.isInstalled = true;
      appState.pwa.canInstall = false;
      appState.pwa.deferredPrompt = null;
      renderApp();
    }
  }
  function activateWaitingUpdate() {
    const waiting = appState.pwa.updateWaiting;
    if (!waiting) return;
    waiting.postMessage({ type: "KHAZNA_SKIP_WAITING" });
  }
  function registerServiceWorker() {
    if (!("serviceWorker" in navigator)) return;
    if (isStandaloneFile() || isChromeExtension()) return;
    if (isCapacitorAndroid()) {
      navigator.serviceWorker.getRegistrations().then((regs) => {
        for (const r of regs) r.unregister().catch(() => {
        });
      }).catch(() => {
      });
      if (typeof caches !== "undefined") {
        caches.keys().then((keys) => {
          for (const k of keys) {
            if (k.startsWith("khazna-shell-")) caches.delete(k).catch(() => {
            });
          }
        }).catch(() => {
        });
      }
      return;
    }
    window.addEventListener("load", async () => {
      try {
        const reg = await navigator.serviceWorker.register("./sw.js", { scope: "./" });
        if (reg.waiting) {
          appState.pwa.updateWaiting = reg.waiting;
          renderApp();
        }
        reg.addEventListener("updatefound", () => {
          const nextWorker = reg.installing;
          if (!nextWorker) return;
          nextWorker.addEventListener("statechange", () => {
            if (nextWorker.state === "installed" && navigator.serviceWorker.controller) {
              appState.pwa.updateWaiting = nextWorker;
              renderApp();
            }
          });
        });
        let reloading = false;
        navigator.serviceWorker.addEventListener("controllerchange", () => {
          if (reloading) return;
          reloading = true;
          window.location.reload();
        });
      } catch {
      }
    });
  }
  function wireGlobalEvents() {
    session.on(async (evt) => {
      if (evt.type === "unlocked") {
        await loadDecryptedVaultData();
        if (!appState.pendingRecoveryKey && evt.method !== "create") {
          withViewTransition(() => renderApp());
        }
      } else if (evt.type === "locked" || evt.type === "wiped") {
        appState.sections = [];
        appState.passwords = [];
        appState.trashedPasswords = [];
        appState.cards = [];
        appState.notes = [];
        appState.twoStepCopy = null;
        const modalRoot = document.getElementById("modal-root");
        if (modalRoot) clearNode(modalRoot);
        renderApp();
      } else if (evt.type === "privacy-blur") {
        const overlay = document.getElementById("privacy-overlay");
        if (overlay) {
          overlay.classList.toggle("hidden", !evt.blurred);
          overlay.setAttribute("aria-hidden", evt.blurred ? "false" : "true");
        }
      } else if (evt.type === "sync-updated" && session.isUnlocked) {
        await loadDecryptedVaultData();
        renderApp();
      }
    });
    session.clipboard.onStatus((ev) => {
      if (ev.type === "cleared") {
        showToast(t(getLang(), "clipboardCleared"), "info", 2200);
      }
    });
    document.addEventListener("visibilitychange", () => {
      session.handleVisibilityChange(document.hidden);
    });
    window.addEventListener("blur", () => {
      if (session.isUnlocked) session.setPrivacyBlur(true);
    });
    window.addEventListener("focus", () => {
      session.setPrivacyBlur(false);
      session.touchActivity();
    });
    const touch = () => session.touchActivity();
    window.addEventListener("pointerdown", touch, { passive: true });
    window.addEventListener("keydown", touch, { passive: true });
    window.addEventListener("online", () => {
      appState.isOnline = true;
      renderApp();
    });
    window.addEventListener("offline", () => {
      appState.isOnline = false;
      renderApp();
    });
    window.addEventListener("beforeinstallprompt", (e) => {
      e.preventDefault();
      appState.pwa.deferredPrompt = e;
      appState.pwa.canInstall = true;
      renderApp();
    });
    window.addEventListener("appinstalled", () => {
      appState.pwa.isInstalled = true;
      appState.pwa.canInstall = false;
      appState.pwa.deferredPrompt = null;
      renderApp();
    });
    window.addEventListener("hashchange", () => {
      if (captureIncomingSyncHash()) {
        if (session.isUnlocked && !appState.pendingRecoveryKey) {
          const code = appState.pendingSyncCode;
          appState.pendingSyncCode = "";
          openDeviceSync("receive", code);
        } else {
          renderApp();
        }
      }
    });
  }
  async function bootstrap() {
    wireGlobalEvents();
    captureIncomingSyncHash();
    await session.init();
    applyThemeAndDirection();
    const params = new URLSearchParams(window.location.search);
    if (params.get("overlay") === "true" || window.location.hash.includes("overlay") || window.__pendingOverlayMode === true) {
      appState.isOverlayMode = true;
      document.documentElement.classList.add("overlay-mode");
      window.__pendingOverlayMode = false;
    }
    if (params.get("popup") === "true" || document.documentElement.dataset.chromePopup === "true") {
      document.documentElement.classList.add("chrome-popup-mode");
    }
    const sharedText = params.get("text") || params.get("title") || "";
    if (sharedText) {
      appState.sharedImportText = sharedText;
      try {
        window.history.replaceState({}, document.title, window.location.pathname);
      } catch {
      }
    }
    renderApp();
    window.__activateOverlayMode = () => {
      appState.isOverlayMode = true;
      document.documentElement.classList.add("overlay-mode");
      renderApp();
    };
    storage.requestPersistentStorage().then((st) => {
      appState.storageStatus = st;
      if (appState.tab === "settings") renderApp();
    });
    computeRuntimeIntegrity().then(() => {
      if (appState.tab === "settings") renderApp();
    });
    registerServiceWorker();
  }
  bootstrap();
})();
