/**
 * Khazna 3-Tier KDF Orchestrator (Crypto-Agile)
 *
 * Tier 1: Locally vendored Argon2id WASM (vendor/argon2.esm.js — pinned hash-wasm@4.13.0)
 * Tier 2: Built-in Pure-JS RFC 9106 Argon2id (byte-identical output to Tier 1)
 * Tier 3: WebCrypto PBKDF2-HMAC-SHA-256 (>= 600,000 iterations) if Argon2id cannot run (e.g. OOM)
 */

import { argon2idPure } from './argon2id-pure.js';
import { KhaznaError, randomBytes, utf8Encode, zeroize } from './utils.js';

export const KDF_ALGO = Object.freeze({
  ARGON2ID: 'argon2id',
  PBKDF2_SHA256: 'pbkdf2-sha256',
});

export const KDF_LIMITS = Object.freeze({
  MIN_ARGON2_MEMORY_KIB: 32768,      // 32 MiB minimum for newly created/upgraded vaults
  MAX_ARGON2_MEMORY_KIB: 524288,     // 512 MiB anti-DoS ceiling
  MIN_ARGON2_ITERATIONS: 3,          // Minimum 3 passes
  MAX_ARGON2_ITERATIONS: 64,
  MIN_PBKDF2_ITERATIONS: 600000,     // OWASP floor for PBKDF2-HMAC-SHA-256
  MAX_PBKDF2_ITERATIONS: 5000000,
  TARGET_MS: 950,                    // Calibrate to ~1 second on device
  KEY_LENGTH: 32,                    // 256-bit KEK
});

let cachedWasmModule = undefined;

/**
 * Attempts to dynamically import the locally vendored Argon2id WASM module.
 * Never makes any external network request.
 * @returns {Promise<Function|null>}
 */
export async function loadVendoredArgon2Wasm() {
  if (cachedWasmModule !== undefined) return cachedWasmModule;
  if (typeof WebAssembly === 'undefined') {
    cachedWasmModule = null;
    return null;
  }
  try {
    // Dynamic runtime specifier keeps Vite/Rollup from failing when optional vendor file is absent
    const vendorPath = ['..', '..', 'vendor', 'argon2.esm.js'].join('/');
    const mod = await import(/* @vite-ignore */ vendorPath);
    if (typeof mod?.argon2id === 'function') {
      cachedWasmModule = mod.argon2id;
      return cachedWasmModule;
    }
  } catch {
    // Vendored WASM not installed or blocked by environment; fall through cleanly to Tier 2.
  }
  cachedWasmModule = null;
  return null;
}

export function _resetKdfCacheForTest() {
  cachedWasmModule = undefined;
}

/**
 * Validates KDF specification bounds.
 * @param {{ kdf: string, params: object }} spec
 * @param {boolean} [enforceMinimums=false]
 */
export function validateKdfSpec(spec, enforceMinimums = false) {
  if (!spec || typeof spec !== 'object') {
    throw new KhaznaError('INVALID_KDF', 'إعدادات اشتقاق المفتاح (KDF) غير صالحة.', 'Invalid KDF specification.');
  }
  const { kdf, params } = spec;
  if (!params || typeof params !== 'object') {
    throw new KhaznaError('INVALID_KDF', 'معاملات اشتقاق المفتاح مفقودة.', 'Missing KDF parameters.');
  }

  if (kdf === KDF_ALGO.ARGON2ID) {
    const { memoryKiB, iterations, parallelism = 1 } = params;
    const minMem = enforceMinimums ? KDF_LIMITS.MIN_ARGON2_MEMORY_KIB : 8 * parallelism;
    const minIter = enforceMinimums ? KDF_LIMITS.MIN_ARGON2_ITERATIONS : 1;
    if (
      !Number.isInteger(memoryKiB) ||
      memoryKiB < minMem ||
      memoryKiB > KDF_LIMITS.MAX_ARGON2_MEMORY_KIB ||
      !Number.isInteger(iterations) ||
      iterations < minIter ||
      iterations > KDF_LIMITS.MAX_ARGON2_ITERATIONS ||
      !Number.isInteger(parallelism) ||
      parallelism < 1 ||
      parallelism > 8
    ) {
      throw new KhaznaError(
        'INVALID_KDF_PARAMS',
        'معاملات Argon2id خارج النطاق الآمن المسموح به.',
        'Argon2id parameters out of allowed safety bounds.'
      );
    }
    return;
  }

  if (kdf === KDF_ALGO.PBKDF2_SHA256) {
    const { iterations } = params;
    const minIter = enforceMinimums ? KDF_LIMITS.MIN_PBKDF2_ITERATIONS : 1000;
    if (
      !Number.isInteger(iterations) ||
      iterations < minIter ||
      iterations > KDF_LIMITS.MAX_PBKDF2_ITERATIONS
    ) {
      throw new KhaznaError(
        'INVALID_KDF_PARAMS',
        'عدد دورات PBKDF2 خارج النطاق الآمن المسموح به.',
        'PBKDF2 iterations out of allowed safety bounds.'
      );
    }
    return;
  }

  throw new KhaznaError(
    'UNSUPPORTED_KDF',
    `خوارزمية اشتقاق المفتاح (${kdf}) غير مدعومة في هذا الإصدار.`,
    `Unsupported KDF algorithm: ${kdf}`
  );
}

/**
 * WebCrypto PBKDF2-HMAC-SHA-256 key derivation.
 */
export async function derivePbkdf2Sha256(passwordBytes, salt, iterations, hashLength = 32) {
  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    passwordBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations,
    },
    baseKey,
    hashLength * 8
  );
  return new Uint8Array(bits);
}

/**
 * Runs KDF directly on the current thread (used inside Web Worker, Node tests, or fallback).
 */
export async function deriveKeyBytesDirect(password, salt, spec, opts = {}) {
  validateKdfSpec(spec, false);
  const pwdBytes = typeof password === 'string' ? utf8Encode(password) : new Uint8Array(password);

  try {
    if (spec.kdf === KDF_ALGO.ARGON2ID) {
      const { memoryKiB, iterations, parallelism = 1 } = spec.params;
      if (!opts.preferPureJs) {
        const wasmFn = await loadVendoredArgon2Wasm();
        if (wasmFn) {
          const raw = await wasmFn({
            password: pwdBytes,
            salt,
            parallelism,
            iterations,
            memorySize: memoryKiB,
            hashLength: KDF_LIMITS.KEY_LENGTH,
            outputType: 'binary',
          });
          return { keyBytes: new Uint8Array(raw), engine: 'argon2id-wasm' };
        }
      }

      const raw = argon2idPure({
        password: pwdBytes,
        salt,
        memorySize: memoryKiB,
        iterations,
        parallelism,
        hashLength: KDF_LIMITS.KEY_LENGTH,
      });
      return { keyBytes: raw, engine: 'argon2id-js' };
    }

    if (spec.kdf === KDF_ALGO.PBKDF2_SHA256) {
      const raw = await derivePbkdf2Sha256(
        pwdBytes,
        salt,
        spec.params.iterations,
        KDF_LIMITS.KEY_LENGTH
      );
      return { keyBytes: raw, engine: 'webcrypto-pbkdf2' };
    }

    throw new KhaznaError('UNSUPPORTED_KDF', 'خوارزمية KDF غير مدعومة.', 'Unsupported KDF.');
  } finally {
    zeroize(pwdBytes);
  }
}

/**
 * Derives 32-byte key material, offloading Argon2id to a Web Worker when in a browser
 * so glassmorphism animations never stall.
 */
export async function deriveKeyBytes(password, salt, spec, opts = {}) {
  const useWorker = opts.useWorker !== false && typeof Worker === 'function';

  if (useWorker && spec.kdf === KDF_ALGO.ARGON2ID) {
    try {
      return await runInKdfWorker(password, salt, spec, opts);
    } catch {
      // Fall back to direct execution if Worker cannot be spawned.
    }
  }

  return deriveKeyBytesDirect(password, salt, spec, opts);
}

function runInKdfWorker(password, salt, spec, opts) {
  return new Promise((resolve, reject) => {
    let workerUrl;
    try {
      workerUrl =
        typeof import.meta !== 'undefined' && import.meta?.url
          ? new URL('./kdf-worker.js', import.meta.url)
          : null;
    } catch {
      workerUrl = null;
    }
    if (!workerUrl) {
      deriveKeyBytesDirect(password, salt, spec, opts).then(resolve, reject);
      return;
    }
    const worker = new Worker(workerUrl, { type: 'module' });
    const pwdBytes = typeof password === 'string' ? utf8Encode(password) : new Uint8Array(password);
    const saltCopy = new Uint8Array(salt);

    const cleanup = () => {
      try {
        worker.terminate();
      } catch {
        // ignore
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
          msg?.code || 'KDF_WORKER_ERROR',
          msg?.ar || 'تعذّر اشتقاق مفتاح التشفير.',
          msg?.en || 'KDF worker error.'
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
        preferPureJs: Boolean(opts.preferPureJs),
      },
      [pwdBytes.buffer, saltCopy.buffer]
    );
  });
}

/**
 * Calibrates KDF parameters to take approximately ~1 second on the current device,
 * strictly respecting security minimums:
 *   - Argon2id: memory >= 32 MiB (32768 KiB), iterations >= 3
 *   - Fallback PBKDF2-HMAC-SHA-256: iterations >= 600,000
 */
export async function calibrateKdf(opts = {}) {
  const targetMs = opts.targetMs ?? KDF_LIMITS.TARGET_MS;
  const samplePassword = randomBytes(16);
  const sampleSalt = randomBytes(16);

  try {
    if (!opts.forcePbkdf2) {
      try {
        let memoryKiB = KDF_LIMITS.MIN_ARGON2_MEMORY_KIB; // 32 MiB
        let iterations = KDF_LIMITS.MIN_ARGON2_ITERATIONS; // 3
        const parallelism = 1;

        const t0 = performance.now();
        const probe = await deriveKeyBytes(
          samplePassword,
          sampleSalt,
          { kdf: KDF_ALGO.ARGON2ID, params: { memoryKiB, iterations, parallelism } },
          { useWorker: opts.useWorker }
        );
        const baselineMs = Math.max(1, performance.now() - t0);
        zeroize(probe.keyBytes);

        if (baselineMs * 2 <= targetMs * 1.15) {
          const t1 = performance.now();
          const probe64 = await deriveKeyBytes(
            samplePassword,
            sampleSalt,
            { kdf: KDF_ALGO.ARGON2ID, params: { memoryKiB: 65536, iterations, parallelism } },
            { useWorker: opts.useWorker }
          );
          const ms64 = Math.max(1, performance.now() - t1);
          zeroize(probe64.keyBytes);
          memoryKiB = 65536;

          if (ms64 < targetMs * 0.8) {
            const scaled = Math.round((iterations * targetMs) / ms64);
            iterations = Math.min(8, Math.max(KDF_LIMITS.MIN_ARGON2_ITERATIONS, scaled));
          }

          return {
            kdf: KDF_ALGO.ARGON2ID,
            params: { memoryKiB, iterations, parallelism },
            engine: probe64.engine,
            elapsedMs: Math.round(ms64 * (iterations / KDF_LIMITS.MIN_ARGON2_ITERATIONS)),
          };
        }

        if (baselineMs < targetMs * 0.75) {
          const scaled = Math.round((iterations * targetMs) / baselineMs);
          iterations = Math.min(6, Math.max(KDF_LIMITS.MIN_ARGON2_ITERATIONS, scaled));
        }

        return {
          kdf: KDF_ALGO.ARGON2ID,
          params: { memoryKiB, iterations, parallelism },
          engine: probe.engine,
          elapsedMs: Math.round(baselineMs * (iterations / KDF_LIMITS.MIN_ARGON2_ITERATIONS)),
        };
      } catch {
        // Argon2id failed (e.g. low-RAM OOM); transparently fall back to PBKDF2 >= 600,000.
      }
    }

    const probeIterations = 100000;
    const t0 = performance.now();
    const probe = await derivePbkdf2Sha256(samplePassword, sampleSalt, probeIterations, 32);
    const probeMs = Math.max(1, performance.now() - t0);
    zeroize(probe);

    const estimated = Math.round((probeIterations * targetMs) / probeMs);
    const rounded = Math.ceil(estimated / 50000) * 50000;
    const iterations = Math.min(
      KDF_LIMITS.MAX_PBKDF2_ITERATIONS,
      Math.max(KDF_LIMITS.MIN_PBKDF2_ITERATIONS, rounded)
    );

    return {
      kdf: KDF_ALGO.PBKDF2_SHA256,
      params: { iterations },
      engine: 'webcrypto-pbkdf2',
      elapsedMs: Math.round((probeMs * iterations) / probeIterations),
    };
  } finally {
    zeroize(samplePassword, sampleSalt);
  }
}
