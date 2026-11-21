/**
 * Dedicated Web Worker for off-main-thread Argon2id execution.
 * Terminated immediately by kdf.js after returning key bytes.
 */

import { deriveKeyBytesDirect } from './kdf.js';
import { zeroize } from './utils.js';

self.onmessage = async (ev) => {
  const { passwordBuffer, saltBuffer, spec, preferPureJs } = ev.data;
  const passwordBytes = new Uint8Array(passwordBuffer);
  const saltBytes = new Uint8Array(saltBuffer);

  try {
    const { keyBytes, engine } = await deriveKeyBytesDirect(passwordBytes, saltBytes, spec, {
      preferPureJs,
    });
    const outBuf = keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength);
    zeroize(keyBytes);
    self.postMessage({ ok: true, keyBytes: outBuf, engine }, [outBuf]);
  } catch (err) {
    self.postMessage({
      ok: false,
      code: err?.code || 'KDF_ERROR',
      ar: err?.ar || 'حدث خطأ أثناء اشتقاق مفتاح التشفير.',
      en: err?.en || err?.message || 'Key derivation failed.',
    });
  } finally {
    zeroize(passwordBytes, saltBytes);
  }
};
