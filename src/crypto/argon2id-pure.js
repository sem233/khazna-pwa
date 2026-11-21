/**
 * RFC 9106 Argon2id (v0x13) + RFC 7693 BLAKE2b — Pure JavaScript Reference Implementation
 *
 * Uses (lo, hi) Uint32 pairs for exact 64-bit little-endian arithmetic with minimal allocations.
 * Verified against the canonical RFC 9106 §5.3 Argon2id test vector.
 * Serves as Tier-2 Argon2id when the vendored WASM binary is absent or WASM is disallowed,
 * producing byte-identical RFC 9106 output to hash-wasm.
 */

import { zeroize } from './utils.js';

// --- RFC 7693 BLAKE2b Constants ---
const BLAKE2B_IV_LO = new Uint32Array([
  0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
  0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
]);
const BLAKE2B_IV_HI = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SIGMA = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
]);

const b2vLo = new Uint32Array(16);
const b2vHi = new Uint32Array(16);
const b2mLo = new Uint32Array(16);
const b2mHi = new Uint32Array(16);

function b2G(a, b, c, d, ix, iy) {
  let aLo = b2vLo[a], aHi = b2vHi[a];
  let bLo = b2vLo[b], bHi = b2vHi[b];
  let cLo = b2vLo[c], cHi = b2vHi[c];
  let dLo = b2vLo[d], dHi = b2vHi[d];

  let s1 = (aLo + bLo) >>> 0;
  let carry = s1 < aLo ? 1 : 0;
  let s2 = (s1 + b2mLo[ix]) >>> 0;
  carry += s2 < s1 ? 1 : 0;
  aHi = (aHi + bHi + b2mHi[ix] + carry) >>> 0;
  aLo = s2;

  let xLo = (dLo ^ aLo) >>> 0;
  let xHi = (dHi ^ aHi) >>> 0;
  dLo = xHi;
  dHi = xLo;

  s1 = (cLo + dLo) >>> 0;
  cHi = (cHi + dHi + (s1 < cLo ? 1 : 0)) >>> 0;
  cLo = s1;

  xLo = (bLo ^ cLo) >>> 0;
  xHi = (bHi ^ cHi) >>> 0;
  bLo = ((xLo >>> 24) | (xHi << 8)) >>> 0;
  bHi = ((xHi >>> 24) | (xLo << 8)) >>> 0;

  s1 = (aLo + bLo) >>> 0;
  carry = s1 < aLo ? 1 : 0;
  s2 = (s1 + b2mLo[iy]) >>> 0;
  carry += s2 < s1 ? 1 : 0;
  aHi = (aHi + bHi + b2mHi[iy] + carry) >>> 0;
  aLo = s2;

  xLo = (dLo ^ aLo) >>> 0;
  xHi = (dHi ^ aHi) >>> 0;
  dLo = ((xLo >>> 16) | (xHi << 16)) >>> 0;
  dHi = ((xHi >>> 16) | (xLo << 16)) >>> 0;

  s1 = (cLo + dLo) >>> 0;
  cHi = (cHi + dHi + (s1 < cLo ? 1 : 0)) >>> 0;
  cLo = s1;

  xLo = (bLo ^ cLo) >>> 0;
  xHi = (bHi ^ cHi) >>> 0;
  bLo = ((xLo << 1) | (xHi >>> 31)) >>> 0;
  bHi = ((xHi << 1) | (xLo >>> 31)) >>> 0;

  b2vLo[a] = aLo; b2vHi[a] = aHi;
  b2vLo[b] = bLo; b2vHi[b] = bHi;
  b2vLo[c] = cLo; b2vHi[c] = cHi;
  b2vLo[d] = dLo; b2vHi[d] = dHi;
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
    b2vLo[14] = (~b2vLo[14]) >>> 0;
    b2vHi[14] = (~b2vHi[14]) >>> 0;
  }

  for (let i = 0; i < 16; i++) {
    const o = i * 8;
    b2mLo[i] = (block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24)) >>> 0;
    b2mHi[i] = (block[o + 4] | (block[o + 5] << 8) | (block[o + 6] << 16) | (block[o + 7] << 24)) >>> 0;
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

/**
 * Unkeyed BLAKE2b hash (RFC 7693).
 * @param {Uint8Array} data
 * @param {number} [outLen=64] 1..64 bytes
 * @returns {Uint8Array}
 */
export function blake2b(data, outLen = 64) {
  if (outLen < 1 || outLen > 64) {
    throw new RangeError('BLAKE2b output length must be 1..64 bytes');
  }
  const hLo = new Uint32Array(BLAKE2B_IV_LO);
  const hHi = new Uint32Array(BLAKE2B_IV_HI);
  hLo[0] = (hLo[0] ^ (0x01010000 | outLen)) >>> 0;

  const block = new Uint8Array(128);
  let tLo = 0;
  let tHi = 0;
  let pos = 0;
  const len = data.length;

  while (len - pos > 128) {
    block.set(data.subarray(pos, pos + 128), 0);
    pos += 128;
    const nextLo = (tLo + 128) >>> 0;
    if (nextLo < tLo) tHi = (tHi + 1) >>> 0;
    tLo = nextLo;
    blake2bCompress(hLo, hHi, block, tLo, tHi, false);
  }

  block.fill(0);
  const rem = len - pos;
  if (rem > 0) {
    block.set(data.subarray(pos, len), 0);
  }
  const nextLo = (tLo + rem) >>> 0;
  if (nextLo < tLo) tHi = (tHi + 1) >>> 0;
  tLo = nextLo;
  blake2bCompress(hLo, hHi, block, tLo, tHi, true);

  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) {
    const wordIdx = i >>> 3;
    const byteInWord = i & 7;
    const word = byteInWord < 4 ? hLo[wordIdx] : hHi[wordIdx];
    out[i] = (word >>> ((byteInWord & 3) * 8)) & 0xff;
  }

  zeroize(hLo, hHi, block, b2vLo, b2vHi, b2mLo, b2mHi);
  return out;
}

function blake2bLong(input, outLen) {
  const prefixed = new Uint8Array(4 + input.length);
  prefixed[0] = outLen & 0xff;
  prefixed[1] = (outLen >>> 8) & 0xff;
  prefixed[2] = (outLen >>> 16) & 0xff;
  prefixed[3] = (outLen >>> 24) & 0xff;
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

const BLOCK_U32 = 256;
const SYNC_POINTS = 4;
const ADDRESSES_IN_BLOCK = 128;

function argon2GB(B, ia, ib, ic, id) {
  const ao = ia << 1, bo = ib << 1, co = ic << 1, do_ = id << 1;
  let aLo = B[ao], aHi = B[ao + 1];
  let bLo = B[bo], bHi = B[bo + 1];
  let cLo = B[co], cHi = B[co + 1];
  let dLo = B[do_], dHi = B[do_ + 1];

  let xl, xh, yl, yh, p0, p1, p2, p3, mid, prodLo, prodHi, mLo, mHi, s1, s2, c1, c2, tLo, tHi;

  // 1) a = fBlaMka(a, b); d = rotr64(d ^ a, 32)
  xl = aLo & 0xffff; xh = aLo >>> 16;
  yl = bLo & 0xffff; yh = bLo >>> 16;
  p0 = xl * yl; p1 = xh * yl; p2 = xl * yh; p3 = xh * yh;
  mid = (p0 >>> 16) + (p1 & 0xffff) + (p2 & 0xffff);
  prodLo = ((p0 & 0xffff) | ((mid & 0xffff) << 16)) >>> 0;
  prodHi = (p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16)) >>> 0;
  mHi = ((prodHi << 1) | (prodLo >>> 31)) >>> 0;
  mLo = (prodLo << 1) >>> 0;
  s1 = (aLo + bLo) >>> 0; c1 = s1 < aLo ? 1 : 0;
  s2 = (s1 + mLo) >>> 0; c2 = s2 < s1 ? 1 : 0;
  aHi = (aHi + bHi + mHi + c1 + c2) >>> 0;
  aLo = s2;

  tLo = (dLo ^ aLo) >>> 0; tHi = (dHi ^ aHi) >>> 0;
  dLo = tHi; dHi = tLo;

  // 2) c = fBlaMka(c, d); b = rotr64(b ^ c, 24)
  xl = cLo & 0xffff; xh = cLo >>> 16;
  yl = dLo & 0xffff; yh = dLo >>> 16;
  p0 = xl * yl; p1 = xh * yl; p2 = xl * yh; p3 = xh * yh;
  mid = (p0 >>> 16) + (p1 & 0xffff) + (p2 & 0xffff);
  prodLo = ((p0 & 0xffff) | ((mid & 0xffff) << 16)) >>> 0;
  prodHi = (p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16)) >>> 0;
  mHi = ((prodHi << 1) | (prodLo >>> 31)) >>> 0;
  mLo = (prodLo << 1) >>> 0;
  s1 = (cLo + dLo) >>> 0; c1 = s1 < cLo ? 1 : 0;
  s2 = (s1 + mLo) >>> 0; c2 = s2 < s1 ? 1 : 0;
  cHi = (cHi + dHi + mHi + c1 + c2) >>> 0;
  cLo = s2;

  tLo = (bLo ^ cLo) >>> 0; tHi = (bHi ^ cHi) >>> 0;
  bLo = ((tLo >>> 24) | (tHi << 8)) >>> 0;
  bHi = ((tHi >>> 24) | (tLo << 8)) >>> 0;

  // 3) a = fBlaMka(a, b); d = rotr64(d ^ a, 16)
  xl = aLo & 0xffff; xh = aLo >>> 16;
  yl = bLo & 0xffff; yh = bLo >>> 16;
  p0 = xl * yl; p1 = xh * yl; p2 = xl * yh; p3 = xh * yh;
  mid = (p0 >>> 16) + (p1 & 0xffff) + (p2 & 0xffff);
  prodLo = ((p0 & 0xffff) | ((mid & 0xffff) << 16)) >>> 0;
  prodHi = (p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16)) >>> 0;
  mHi = ((prodHi << 1) | (prodLo >>> 31)) >>> 0;
  mLo = (prodLo << 1) >>> 0;
  s1 = (aLo + bLo) >>> 0; c1 = s1 < aLo ? 1 : 0;
  s2 = (s1 + mLo) >>> 0; c2 = s2 < s1 ? 1 : 0;
  aHi = (aHi + bHi + mHi + c1 + c2) >>> 0;
  aLo = s2;

  tLo = (dLo ^ aLo) >>> 0; tHi = (dHi ^ aHi) >>> 0;
  dLo = ((tLo >>> 16) | (tHi << 16)) >>> 0;
  dHi = ((tHi >>> 16) | (tLo << 16)) >>> 0;

  // 4) c = fBlaMka(c, d); b = rotr64(b ^ c, 63) == rotl64(b ^ c, 1)
  xl = cLo & 0xffff; xh = cLo >>> 16;
  yl = dLo & 0xffff; yh = dLo >>> 16;
  p0 = xl * yl; p1 = xh * yl; p2 = xl * yh; p3 = xh * yh;
  mid = (p0 >>> 16) + (p1 & 0xffff) + (p2 & 0xffff);
  prodLo = ((p0 & 0xffff) | ((mid & 0xffff) << 16)) >>> 0;
  prodHi = (p3 + (p1 >>> 16) + (p2 >>> 16) + (mid >>> 16)) >>> 0;
  mHi = ((prodHi << 1) | (prodLo >>> 31)) >>> 0;
  mLo = (prodLo << 1) >>> 0;
  s1 = (cLo + dLo) >>> 0; c1 = s1 < cLo ? 1 : 0;
  s2 = (s1 + mLo) >>> 0; c2 = s2 < s1 ? 1 : 0;
  cHi = (cHi + dHi + mHi + c1 + c2) >>> 0;
  cLo = s2;

  tLo = (bLo ^ cLo) >>> 0; tHi = (bHi ^ cHi) >>> 0;
  bLo = ((tLo << 1) | (tHi >>> 31)) >>> 0;
  bHi = ((tHi << 1) | (tLo >>> 31)) >>> 0;

  B[ao] = aLo; B[ao + 1] = aHi;
  B[bo] = bLo; B[bo + 1] = bHi;
  B[co] = cLo; B[co + 1] = cHi;
  B[do_] = dLo; B[do_ + 1] = dHi;
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
      b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
      b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15
    );
  }

  for (let i = 0; i < 8; i++) {
    const b = i * 2;
    blake2RoundNoMsg(
      blockR,
      b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
      b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113
    );
  }

  for (let i = 0; i < BLOCK_U32; i++) {
    nextBuf[nextOff + i] = (blockTmp[i] ^ blockR[i]) >>> 0;
  }
}

function nextAddresses(addrBlock, inputBlock, zeroBlock, blockR, blockTmp) {
  const nextLo = (inputBlock[12] + 1) >>> 0;
  if (nextLo === 0) inputBlock[13] = (inputBlock[13] + 1) >>> 0;
  inputBlock[12] = nextLo;

  fillBlock(zeroBlock, 0, inputBlock, 0, addrBlock, 0, false, blockR, blockTmp);
  fillBlock(zeroBlock, 0, addrBlock, 0, addrBlock, 0, false, blockR, blockTmp);
}

function bytesToBlockU32(bytes, dst, dstOff) {
  for (let i = 0; i < BLOCK_U32; i++) {
    const o = i * 4;
    dst[dstOff + i] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
  }
}

function blockU32ToBytes(src, srcOff) {
  const out = new Uint8Array(1024);
  for (let i = 0; i < BLOCK_U32; i++) {
    const w = src[srcOff + i];
    const o = i * 4;
    out[o] = w & 0xff;
    out[o + 1] = (w >>> 8) & 0xff;
    out[o + 2] = (w >>> 16) & 0xff;
    out[o + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

function writeLE32(buf, offset, val) {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 16) & 0xff;
  buf[offset + 3] = (val >>> 24) & 0xff;
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
  const x = (j1Big * j1Big) >> 32n;
  const y = Number((BigInt(refAreaSize) * x) >> 32n);
  const relPos = refAreaSize - 1 - y;

  const startPos = (pass !== 0 && slice !== SYNC_POINTS - 1)
    ? (slice + 1) * segmentLength
    : 0;

  return (startPos + relPos) % laneLength;
}

/**
 * Computes RFC 9106 Argon2id (v0x13).
 */
export function argon2idPure({
  password,
  salt,
  memorySize,
  iterations,
  parallelism = 1,
  hashLength = 32,
  secret = new Uint8Array(0),
  associatedData = new Uint8Array(0),
  type = 2,
}) {
  if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) {
    throw new TypeError('Argon2id requires Uint8Array password and salt');
  }
  if (!Number.isInteger(parallelism) || parallelism < 1) {
    throw new RangeError('Argon2id parallelism must be >= 1');
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new RangeError('Argon2id iterations must be >= 1');
  }
  if (!Number.isInteger(hashLength) || hashLength < 4) {
    throw new RangeError('Argon2id hashLength must be >= 4');
  }

  const minMemory = 8 * parallelism;
  if (!Number.isInteger(memorySize) || memorySize < minMemory) {
    throw new RangeError(`Argon2id memorySize must be >= ${minMemory} KiB`);
  }

  const version = 0x13;
  const memoryBlocks = 4 * parallelism * Math.floor(memorySize / (4 * parallelism));
  const laneLength = memoryBlocks / parallelism;
  const segmentLength = laneLength / SYNC_POINTS;

  const h0InputLen = 40 + password.length + salt.length + secret.length + associatedData.length;
  const h0Input = new Uint8Array(h0InputLen);
  let p = 0;
  writeLE32(h0Input, p, parallelism); p += 4;
  writeLE32(h0Input, p, hashLength); p += 4;
  writeLE32(h0Input, p, memorySize); p += 4;
  writeLE32(h0Input, p, iterations); p += 4;
  writeLE32(h0Input, p, version); p += 4;
  writeLE32(h0Input, p, type); p += 4;
  writeLE32(h0Input, p, password.length); p += 4;
  h0Input.set(password, p); p += password.length;
  writeLE32(h0Input, p, salt.length); p += 4;
  h0Input.set(salt, p); p += salt.length;
  writeLE32(h0Input, p, secret.length); p += 4;
  h0Input.set(secret, p); p += secret.length;
  writeLE32(h0Input, p, associatedData.length); p += 4;
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
        const dataIndependent = type === 1 || (type === 2 && pass === 0 && slice < 2);

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
          let prevOffset = (currOffset % laneLength === 0)
            ? currOffset + laneLength - 1
            : currOffset - 1;

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

            const refLane = (pass === 0 && slice === 0) ? lane : (j2 % parallelism);
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
