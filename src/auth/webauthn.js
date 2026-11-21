/**
 * Khazna WebAuthn Biometric Unlock (Android Chrome & Samsung Internet)
 *
 * Mode 1 (Preferred, cryptographically bound): WebAuthn Platform Authenticator + PRF Extension
 *   - Hardware biometric prompt (userVerification: "required") -> 32-byte PRF output ->
 *     HKDF-SHA-256 -> wraps/unwraps the DEK directly.
 *   - Explicitly handles providers (common on Android) that report `prf.enabled: true`
 *     on create() and only emit `prf.results.first` during get().
 *
 * Mode 2 (Honest Fallback when PRF is unavailable): Convenience Unlock
 *   - Never claims hardware key wrapping. Shows an explicit warning and lets the user disable it.
 *   - Keeps a RAM-only ephemeral AES-GCM wrapper of the DEK inside this module's private closure
 *     (NEVER written to IndexedDB/localStorage).
 *   - Demands Master Password after every cold start (page reload clears RAM) AND every 24 hours.
 *   - Verifies the real WebAuthn ECDSA P-256 / RS256 assertion signature over
 *     (authenticatorData || SHA-256(clientDataJSON)) + fresh challenge via WebCrypto.
 */

import {
  createWebAuthnPrfWrapper,
  unwrapDekWithWebAuthnPrf,
} from '../crypto/vault-crypto.js';
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  concatBytes,
  KhaznaError,
  randomBytes,
  sha256Bytes,
  utf8Decode,
  utf8Encode,
  zeroize,
} from '../crypto/utils.js';

export const CONVENIENCE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

let convenienceRamState = null;

export function isWebAuthnSupported(env = globalThis) {
  return Boolean(
    env.PublicKeyCredential &&
    env.navigator?.credentials &&
    typeof env.navigator.credentials.create === 'function' &&
    typeof env.navigator.credentials.get === 'function'
  );
}

export async function isPlatformAuthenticatorAvailable(env = globalThis) {
  if (!isWebAuthnSupported(env)) return false;
  try {
    return await env.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export async function detectPrfCapability(env = globalThis) {
  if (!isWebAuthnSupported(env)) return 'unsupported';
  try {
    if (typeof env.PublicKeyCredential.getClientCapabilities === 'function') {
      const caps = await env.PublicKeyCredential.getClientCapabilities();
      if (caps && 'extension:prf' in caps) {
        return caps['extension:prf'] ? 'supported' : 'unsupported';
      }
    }
  } catch {
    // Older browsers lack getClientCapabilities; probe during enrollment.
  }
  return 'probe-required';
}

function normalizeWebAuthnError(err) {
  if (err instanceof KhaznaError) return err;
  const name = err?.name || '';
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return new KhaznaError(
      'WEBAUTHN_CANCELLED',
      'تم إلغاء التحقق بالبصمة أو انتهت مهلة الطلب.',
      'Biometric verification was cancelled or timed out.',
      err
    );
  }
  if (name === 'SecurityError') {
    return new KhaznaError(
      'WEBAUTHN_HTTPS_REQUIRED',
      'يتطلب فتح البصمة تشغيل خزنة عبر اتصال HTTPS آمن.',
      'WebAuthn requires a secure HTTPS origin.',
      err
    );
  }
  if (name === 'InvalidStateError') {
    return new KhaznaError(
      'WEBAUTHN_ALREADY_REGISTERED',
      'بيانات البصمة مسجّلة بالفعل على هذا الجهاز.',
      'Authenticator credential already registered.',
      err
    );
  }
  return new KhaznaError(
    'WEBAUTHN_ERROR',
    'تعذّر إتمام عملية البصمة على هذا الجهاز.',
    err?.message || 'WebAuthn operation failed.',
    err
  );
}

function extractPrfFirstBytes(cred) {
  const ext = typeof cred?.getClientExtensionResults === 'function'
    ? cred.getClientExtensionResults()
    : null;
  const first = ext?.prf?.results?.first;
  if (!first) return null;
  const bytes = first instanceof Uint8Array
    ? new Uint8Array(first)
    : ArrayBuffer.isView(first)
      ? new Uint8Array(first.buffer.slice(first.byteOffset, first.byteOffset + first.byteLength))
      : first instanceof ArrayBuffer
        ? new Uint8Array(first.slice(0))
        : null;
  return bytes && bytes.length >= 32 ? bytes.subarray(0, 32) : null;
}

function extractAttestationPublicKey(response) {
  try {
    const spkiBuf = typeof response?.getPublicKey === 'function' ? response.getPublicKey() : null;
    const alg = typeof response?.getPublicKeyAlgorithm === 'function'
      ? response.getPublicKeyAlgorithm()
      : -7;
    if (!spkiBuf) return null;
    return {
      spkiB64: bytesToBase64(new Uint8Array(spkiBuf)),
      alg,
    };
  } catch {
    return null;
  }
}

function derEcdsaToP1363(der) {
  if (der.length === 64) return der;
  if (der[0] !== 0x30) throw new Error('Invalid DER signature sequence');
  let offset = 2;
  if (der[1] & 0x80) {
    offset = 2 + (der[1] & 0x7f);
  }
  if (der[offset] !== 0x02) throw new Error('Invalid DER r integer');
  const rLen = der[offset + 1];
  const rBytes = der.subarray(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;

  if (der[offset] !== 0x02) throw new Error('Invalid DER s integer');
  const sLen = der[offset + 1];
  const sBytes = der.subarray(offset + 2, offset + 2 + sLen);

  const out = new Uint8Array(64);
  const rClean = rBytes.length > 32 ? rBytes.subarray(rBytes.length - 32) : rBytes;
  const sClean = sBytes.length > 32 ? sBytes.subarray(sBytes.length - 32) : sBytes;
  out.set(rClean, 32 - rClean.length);
  out.set(sClean, 64 - sClean.length);
  return out;
}

export async function verifyWebAuthnAssertion({
  assertion,
  expectedChallenge,
  expectedOrigin,
  publicKeySpkiB64,
  publicKeyAlg = -7,
}) {
  const resp = assertion?.response;
  if (!resp?.clientDataJSON || !resp?.authenticatorData || !resp?.signature) {
    throw new KhaznaError(
      'WEBAUTHN_INVALID_ASSERTION',
      'استجابة البصمة غير مكتملة.',
      'Incomplete WebAuthn assertion response.'
    );
  }

  const clientDataBytes = new Uint8Array(resp.clientDataJSON);
  const authDataBytes = new Uint8Array(resp.authenticatorData);
  const sigBytes = new Uint8Array(resp.signature);

  const clientData = JSON.parse(utf8Decode(clientDataBytes));
  if (clientData.type !== 'webauthn.get') {
    throw new KhaznaError('WEBAUTHN_INVALID_TYPE', 'نوع تحقق البصمة غير صالح.', 'Invalid WebAuthn ceremony type.');
  }
  const expectedChallengeB64Url = bytesToBase64Url(expectedChallenge);
  if (clientData.challenge !== expectedChallengeB64Url) {
    throw new KhaznaError('WEBAUTHN_CHALLENGE_MISMATCH', 'فشل التحقق من رمز التحدي للبصمة.', 'WebAuthn challenge mismatch.');
  }
  if (expectedOrigin && clientData.origin !== expectedOrigin) {
    throw new KhaznaError('WEBAUTHN_ORIGIN_MISMATCH', 'نطاق التحقق بالبصمة غير متطابق.', 'WebAuthn origin mismatch.');
  }

  if (authDataBytes.length < 37) {
    throw new KhaznaError('WEBAUTHN_BAD_AUTHDATA', 'بيانات المصادق غير صالحة.', 'Truncated authenticatorData.');
  }
  const flags = authDataBytes[32];
  if ((flags & 0x05) !== 0x05) {
    throw new KhaznaError(
      'WEBAUTHN_UV_REQUIRED',
      'لم يكتمل التحقق الحيوي (البصمة/الوجه) المطلوب.',
      'User Presence and User Verification flags are required.'
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
      keyAlg = { name: 'ECDSA', namedCurve: 'P-256' };
      verifyAlg = { name: 'ECDSA', hash: 'SHA-256' };
      finalSig = derEcdsaToP1363(sigBytes);
    } else if (publicKeyAlg === -257) {
      keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      verifyAlg = { name: 'RSASSA-PKCS1-v1_5' };
    } else {
      throw new KhaznaError(
        'WEBAUTHN_UNSUPPORTED_ALG',
        'خوارزمية توقيع المصادق غير مدعومة.',
        `Unsupported WebAuthn public key algorithm: ${publicKeyAlg}`
      );
    }

    const pubKey = await globalThis.crypto.subtle.importKey('spki', spki, keyAlg, false, ['verify']);
    const ok = await globalThis.crypto.subtle.verify(verifyAlg, pubKey, finalSig, signedData);
    if (!ok) {
      throw new KhaznaError(
        'WEBAUTHN_SIGNATURE_INVALID',
        'فشل التحقق التشفيري من توقيع البصمة.',
        'WebAuthn assertion signature verification failed.'
      );
    }
  }

  return true;
}

export async function enrollBiometric({
  header,
  extractableDek,
  rpId,
  rpName = 'Khazna (خزنة)',
  env = globalThis,
}) {
  if (!isWebAuthnSupported(env)) {
    throw new KhaznaError(
      'WEBAUTHN_UNSUPPORTED',
      'هذا المتصفح لا يدعم WebAuthn لفتح الخزنة بالبصمة.',
      'WebAuthn is not supported in this browser.'
    );
  }

  const effectiveRpId = rpId || env.location?.hostname || 'localhost';
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
          name: 'khazna-local-vault',
          displayName: 'Khazna Vault',
        },
        challenge,
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        attestation: 'none',
        timeout: 60000,
        extensions: {
          prf: {
            eval: { first: prfSalt },
          },
        },
      },
    });
  } catch (err) {
    throw normalizeWebAuthnError(err);
  }

  if (!cred || !cred.rawId) {
    throw new KhaznaError(
      'WEBAUTHN_CREATE_FAILED',
      'لم يُعِد الجهاز بيانات مصادقة صالحة.',
      'WebAuthn credential creation returned empty result.'
    );
  }

  const credentialId = bytesToBase64Url(new Uint8Array(cred.rawId));
  const prfSaltB64 = bytesToBase64(prfSalt);
  const pubKeyInfo = extractAttestationPublicKey(cred.response);

  let prfOutput = extractPrfFirstBytes(cred);

  if (!prfOutput) {
    const ext = typeof cred.getClientExtensionResults === 'function'
      ? cred.getClientExtensionResults()
      : null;
    const shouldProbeGet = ext?.prf?.enabled !== false;

    if (shouldProbeGet) {
      try {
        const probeAssertion = await env.navigator.credentials.get({
          publicKey: {
            rpId: effectiveRpId,
            challenge: randomBytes(32),
            allowCredentials: [
              {
                type: 'public-key',
                id: base64UrlToBytes(credentialId),
                transports: ['internal'],
              },
            ],
            userVerification: 'required',
            timeout: 60000,
            extensions: {
              prf: {
                eval: { first: prfSalt },
              },
            },
          },
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
        prfSaltB64,
      });
      return {
        mode: 'prf',
        wrapper,
      };
    } finally {
      zeroize(prfOutput);
    }
  }

  return {
    mode: 'prf-unavailable',
    pendingConvenience: {
      mode: 'convenience',
      credentialId,
      publicKeySpki: pubKeyInfo?.spkiB64 || null,
      publicKeyAlg: pubKeyInfo?.alg ?? -7,
      createdAt: new Date().toISOString(),
    },
    warningAr:
      'جهازك أو متصفحك لا يدعم امتداد WebAuthn PRF للتشفير المرتبط مباشرة بالبصمة. ' +
      'يمكنك تفعيل "فتح البصمة السريع (وضع الراحة)" الذي يحتفظ بمفتاح مؤقت في الذاكرة فقط، ' +
      'ويُلزمك بإدخال كلمة المرور الرئيسية بعد كل إعادة تشغيل للتطبيق وكل ٢٤ ساعة، ويمكنك تعطيله في أي وقت.',
    warningEn:
      'Your device/browser does not support the WebAuthn PRF extension for cryptographically bound biometric wrapping. ' +
      'You may enable "Convenience Biometric Unlock", which keeps an ephemeral wrapper in RAM only, ' +
      'still demands your Master Password after every cold start and every 24 hours, and can be disabled anytime.',
  };
}

export async function armConvenienceRamSession(vaultId, extractableDek, masterUnlockedAt = Date.now()) {
  clearConvenienceRamSession();
  const ephemKey = await globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
  const iv = randomBytes(12);
  const wrapped = await globalThis.crypto.subtle.wrapKey(
    'raw',
    extractableDek,
    ephemKey,
    { name: 'AES-GCM', iv }
  );
  convenienceRamState = {
    vaultId,
    ephemKey,
    iv,
    wrappedDek: new Uint8Array(wrapped),
    armedAt: masterUnlockedAt,
  };
}

export function clearConvenienceRamSession() {
  if (convenienceRamState) {
    zeroize(convenienceRamState.iv, convenienceRamState.wrappedDek);
    convenienceRamState = null;
  }
}

export function getConvenienceStatus(header, now = Date.now()) {
  const wa = header?.wrappers?.webauthn;
  if (!wa || wa.mode !== 'convenience') {
    return { enabled: false, ready: false, reason: 'disabled' };
  }
  if (!convenienceRamState || convenienceRamState.vaultId !== header.vaultId) {
    return { enabled: true, ready: false, reason: 'cold-start' };
  }
  const age = now - convenienceRamState.armedAt;
  if (age >= CONVENIENCE_MAX_AGE_MS || age < 0) {
    clearConvenienceRamSession();
    return { enabled: true, ready: false, reason: 'expired-24h' };
  }
  return {
    enabled: true,
    ready: true,
    reason: 'ready',
    remainingMs: CONVENIENCE_MAX_AGE_MS - age,
  };
}

export async function unlockWithBiometric(header, opts = {}) {
  const env = opts.env || globalThis;
  const wa = header?.wrappers?.webauthn;
  if (!wa || !wa.credentialId) {
    throw new KhaznaError(
      'BIOMETRIC_NOT_ENABLED',
      'فتح الخزنة بالبصمة غير مفعّل في الإعدادات.',
      'Biometric unlock is not enabled.'
    );
  }
  if (!isWebAuthnSupported(env)) {
    throw new KhaznaError(
      'WEBAUTHN_UNSUPPORTED',
      'هذا المتصفح لا يدعم WebAuthn.',
      'WebAuthn is not supported in this browser.'
    );
  }

  const effectiveRpId = opts.rpId || env.location?.hostname || 'localhost';
  const challenge = randomBytes(32);

  if (wa.mode === 'prf') {
    const prfSalt = base64ToBytes(wa.prfSalt);
    let assertion;
    try {
      assertion = await env.navigator.credentials.get({
        publicKey: {
          rpId: effectiveRpId,
          challenge,
          allowCredentials: [
            {
              type: 'public-key',
              id: base64UrlToBytes(wa.credentialId),
              transports: ['internal'],
            },
          ],
          userVerification: 'required',
          timeout: 60000,
          extensions: {
            prf: {
              eval: { first: prfSalt },
            },
          },
        },
      });
    } catch (err) {
      throw normalizeWebAuthnError(err);
    }

    const prfOutput = extractPrfFirstBytes(assertion);
    if (!prfOutput) {
      throw new KhaznaError(
        'WEBAUTHN_PRF_MISSING',
        'لم يُعِد الجهاز مفتاح PRF من البصمة — يُرجى الفتح بكلمة المرور الرئيسية.',
        'Authenticator did not return PRF output. Unlock with Master Password.'
      );
    }

    try {
      const dek = await unwrapDekWithWebAuthnPrf(header, prfOutput, { extractable: false });
      return { dek, mode: 'prf' };
    } finally {
      zeroize(prfOutput);
    }
  }

  if (wa.mode === 'convenience') {
    const status = getConvenienceStatus(header, opts.now ?? Date.now());
    if (!status.ready) {
      const arMsg = status.reason === 'expired-24h'
        ? 'انتهت مهلة ٢٤ ساعة لوضع البصمة السريع — أدخل كلمة المرور الرئيسية لإعادة التفعيل.'
        : 'تمت إعادة تشغيل التطبيق — أدخل كلمة المرور الرئيسية أولاً (وضع البصمة السريع مؤقت في الذاكرة فقط).';
      const enMsg = status.reason === 'expired-24h'
        ? '24-hour window expired for Convenience Biometric Unlock — enter Master Password.'
        : 'Cold start detected — Master Password is required (Convenience Unlock is RAM-only).';
      throw new KhaznaError('CONVENIENCE_MASTER_REQUIRED', arMsg, enMsg);
    }

    let assertion;
    try {
      assertion = await env.navigator.credentials.get({
        publicKey: {
          rpId: effectiveRpId,
          challenge,
          allowCredentials: [
            {
              type: 'public-key',
              id: base64UrlToBytes(wa.credentialId),
              transports: ['internal'],
            },
          ],
          userVerification: 'required',
          timeout: 60000,
        },
      });
    } catch (err) {
      throw normalizeWebAuthnError(err);
    }

    await verifyWebAuthnAssertion({
      assertion,
      expectedChallenge: challenge,
      expectedOrigin: opts.expectedOrigin ?? env.location?.origin,
      publicKeySpkiB64: wa.publicKeySpki,
      publicKeyAlg: wa.publicKeyAlg ?? -7,
    });

    const dek = await globalThis.crypto.subtle.unwrapKey(
      'raw',
      convenienceRamState.wrappedDek,
      convenienceRamState.ephemKey,
      { name: 'AES-GCM', iv: convenienceRamState.iv },
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return { dek, mode: 'convenience' };
  }

  throw new KhaznaError('INVALID_BIOMETRIC_MODE', 'إعدادات البصمة غير معروفة.', 'Unknown biometric wrapper mode.');
}

export async function verifyBiometricForReauth(header, opts = {}) {
  const env = opts.env || globalThis;
  const wa = header?.wrappers?.webauthn;
  if (!wa?.credentialId || !isWebAuthnSupported(env)) {
    throw new KhaznaError(
      'BIOMETRIC_NOT_AVAILABLE',
      'البصمة غير مفعّلة — استخدم كلمة المرور الرئيسية.',
      'Biometric re-authentication unavailable.'
    );
  }
  const effectiveRpId = opts.rpId || env.location?.hostname || 'localhost';
  const challenge = randomBytes(32);

  let assertion;
  try {
    assertion = await env.navigator.credentials.get({
      publicKey: {
        rpId: effectiveRpId,
        challenge,
        allowCredentials: [
          {
            type: 'public-key',
            id: base64UrlToBytes(wa.credentialId),
            transports: ['internal'],
          },
        ],
        userVerification: 'required',
        timeout: 60000,
      },
    });
  } catch (err) {
    throw normalizeWebAuthnError(err);
  }

  await verifyWebAuthnAssertion({
    assertion,
    expectedChallenge: challenge,
    expectedOrigin: opts.expectedOrigin ?? env.location?.origin,
    publicKeySpkiB64: wa.publicKeySpki || null,
    publicKeyAlg: wa.publicKeyAlg ?? -7,
  });

  return true;
}
