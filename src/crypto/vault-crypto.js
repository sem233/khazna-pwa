/**
 * Khazna Core Vault Cryptography
 *
 * - AES-256-GCM via WebCrypto with fresh 96-bit IVs and canonical AAD binding
 *   { id, type, schemaVersion, vaultId }.
 * - Random 256-bit DEK wrapped independently by Master Password, WebAuthn PRF, and Recovery Key.
 * - Operational DEK is ALWAYS unwrapped as a non-extractable CryptoKey (raw bytes never touch JS heap).
 * - Master password change re-wraps only the DEK atomically without re-encrypting every record.
 */

import { deriveKeyBytes, KDF_ALGO, validateKdfSpec } from './kdf.js';
import {
  base64ToBytes,
  buildAAD,
  bytesToBase64,
  decodeRecoveryKey,
  encodeRecoveryKey,
  KhaznaError,
  randomBytes,
  randomId,
  randomInt,
  utf8Decode,
  utf8Encode,
  zeroize,
} from './utils.js';

export const VAULT_HEADER_VERSION = 1;
export const RECORD_SCHEMA_VERSION = 1;
export const BACKUP_FORMAT_ID = 'khazna-vault-backup';
export const BACKUP_FORMAT_VERSION = 1;
export const MIN_MASTER_PASSWORD_LEN = 12;

const HKDF_INFO_RECOVERY = utf8Encode('khazna-v1-recovery-dek-wrap');
const HKDF_INFO_WEBAUTHN = utf8Encode('khazna-v1-webauthn-prf-dek-wrap');

const CHARSETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}:;,.?/~',
  lookalikes: /[0Oo1Il|]/g,
});

const PASSPHRASE_WORDS = Object.freeze([
  'amber', 'anchor', 'apple', 'apron', 'arbor', 'arrow', 'atlas', 'autumn',
  'badge', 'baker', 'bamboo', 'banner', 'barley', 'barrel', 'basalt', 'basket',
  'beacon', 'beaver', 'berry', 'birch', 'bison', 'blanket', 'blossom', 'boulder',
  'branch', 'breeze', 'bridge', 'bronze', 'brook', 'bucket', 'button', 'cabin',
  'cactus', 'camel', 'candle', 'cannon', 'canopy', 'canyon', 'canvas', 'captain',
  'caravan', 'carbon', 'carpet', 'carrot', 'castle', 'cedar', 'cellar', 'chalk',
  'chapter', 'cherry', 'chisel', 'cider', 'cinnamon', 'circle', 'citadel', 'citrus',
  'clay', 'cliff', 'clover', 'cobalt', 'coffee', 'comet', 'compass', 'copper',
  'coral', 'corner', 'cotton', 'cougar', 'cradle', 'crater', 'crayon', 'creek',
  'cricket', 'crown', 'crystal', 'curtain', 'cushion', 'cypress', 'dagger', 'daisy',
  'dancer', 'dawn', 'delta', 'desert', 'diamond', 'dolphin', 'domino', 'donkey',
  'dragon', 'drawer', 'drift', 'drum', 'eagle', 'earth', 'eclipse', 'elder',
  'ember', 'emerald', 'engine', 'falcon', 'feather', 'fennel', 'ferret', 'fern',
  'fiddle', 'fig', 'filter', 'finch', 'fjord', 'flame', 'flannel', 'flint',
  'flower', 'flute', 'forest', 'fossil', 'fountain', 'fox', 'frost', 'funnel',
  'galaxy', 'garden', 'garlic', 'garnet', 'gazelle', 'geyser', 'ginger', 'glacier',
  'glider', 'globe', 'granite', 'grape', 'gravel', 'griffin', 'grove', 'guitar',
  'hammer', 'harbor', 'harvest', 'hawk', 'hazel', 'heather', 'helmet', 'heron',
  'hickory', 'hollow', 'honey', 'horizon', 'hornet', 'humble', 'ibis', 'icicle',
  'indigo', 'island', 'ivory', 'jacket', 'jade', 'jaguar', 'jasmine', 'jasper',
  'jigsaw', 'juniper', 'kayak', 'kettle', 'kestrel', 'kingdom', 'kitten', 'koala',
  'ladder', 'lagoon', 'lantern', 'larch', 'laser', 'laurel', 'lava', 'lemon',
  'leopard', 'library', 'lichen', 'lilac', 'linden', 'linen', 'lizard', 'lobster',
  'locket', 'lotus', 'lumber', 'lunar', 'lynx', 'magnet', 'magpie', 'mango',
  'mantle', 'maple', 'marble', 'market', 'marmot', 'meadow', 'melon', 'mercury',
  'meteor', 'miller', 'mint', 'mirror', 'mitten', 'monarch', 'monkey', 'monsoon',
  'mosaic', 'moss', 'mountain', 'muffin', 'mulberry', 'mustard', 'narwhal', 'nebula',
  'nectar', 'needle', 'nettle', 'nickel', 'nimbus', 'noodle', 'nutmeg', 'oasis',
  'obsidian', 'ocean', 'ocelot', 'olive', 'onyx', 'opal', 'orange', 'orchard',
  'orchid', 'oriole', 'osprey', 'otter', 'owl', 'oyster', 'paddle', 'palace',
  'palm', 'panda', 'panther', 'papaya', 'paper', 'parrot', 'parsley', 'pasture',
  'pebble', 'pelican', 'pencil', 'penguin', 'peony', 'pepper', 'perch', 'petrel',
]);

export function validateMasterPasswordPolicy(password) {
  if (typeof password !== 'string') {
    throw new KhaznaError(
      'WEAK_MASTER_PASSWORD',
      'يجب إدخال كلمة مرور رئيسية صالحة.',
      'Master password must be a string.'
    );
  }
  const codePoints = Array.from(password).length;
  if (codePoints < MIN_MASTER_PASSWORD_LEN) {
    throw new KhaznaError(
      'MASTER_PASSWORD_TOO_SHORT',
      `يجب ألا تقل كلمة المرور الرئيسية عن ${MIN_MASTER_PASSWORD_LEN} حرفاً.`,
      `Master password must be at least ${MIN_MASTER_PASSWORD_LEN} characters long.`
    );
  }
}

export async function deriveHkdfWrapKey(ikm, salt, info) {
  const baseKey = await globalThis.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return globalThis.crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

async function importAesWrapKey(rawKek) {
  return globalThis.crypto.subtle.importKey(
    'raw',
    rawKek,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

async function wrapDek(extractableDek, kek, vaultId, wrapperId) {
  const iv = randomBytes(12);
  const additionalData = buildAAD({
    id: `wrapper-${wrapperId}`,
    type: 'dek-wrapper',
    schemaVersion: VAULT_HEADER_VERSION,
    vaultId,
  });
  const wrapped = await globalThis.crypto.subtle.wrapKey(
    'raw',
    extractableDek,
    kek,
    { name: 'AES-GCM', iv, additionalData }
  );
  return {
    iv: bytesToBase64(iv),
    wrappedDek: bytesToBase64(new Uint8Array(wrapped)),
  };
}

async function unwrapDek(wrapper, kek, vaultId, wrapperId, extractable = false) {
  const iv = base64ToBytes(wrapper.iv);
  const wrappedBytes = base64ToBytes(wrapper.wrappedDek);
  const additionalData = buildAAD({
    id: `wrapper-${wrapperId}`,
    type: 'dek-wrapper',
    schemaVersion: VAULT_HEADER_VERSION,
    vaultId,
  });

  return globalThis.crypto.subtle.unwrapKey(
    'raw',
    wrappedBytes,
    kek,
    { name: 'AES-GCM', iv, additionalData },
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  );
}

export async function createVaultCrypto({
  masterPassword,
  kdfSpec,
  enforceMinimums = true,
  useWorker = true,
}) {
  validateMasterPasswordPolicy(masterPassword);
  validateKdfSpec(kdfSpec, enforceMinimums);

  const vaultId = randomId('vault');
  const now = new Date().toISOString();

  const tempDek = await globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const passwordSalt = randomBytes(16);
  const recoveryKeyBytes = randomBytes(32);
  const recoverySalt = randomBytes(16);

  let passwordKekBytes = null;
  try {
    const derived = await deriveKeyBytes(masterPassword, passwordSalt, kdfSpec, { useWorker });
    passwordKekBytes = derived.keyBytes;
    const passwordKek = await importAesWrapKey(passwordKekBytes);
    const passwordWrapped = await wrapDek(tempDek, passwordKek, vaultId, 'password');

    const recoveryKek = await deriveHkdfWrapKey(recoveryKeyBytes, recoverySalt, HKDF_INFO_RECOVERY);
    const recoveryWrapped = await wrapDek(tempDek, recoveryKek, vaultId, 'recovery');
    const recoveryKeyFormatted = await encodeRecoveryKey(recoveryKeyBytes);

    const activeDek = await unwrapDek(passwordWrapped, passwordKek, vaultId, 'password', false);

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
          updatedAt: now,
        },
        recovery: {
          salt: bytesToBase64(recoverySalt),
          iv: recoveryWrapped.iv,
          wrappedDek: recoveryWrapped.wrappedDek,
          createdAt: now,
        },
        webauthn: null,
      },
      security: {
        failedAttempts: 0,
        lockoutUntil: 0,
        wipeAfterFailures: 0,
        lastMasterUnlockAt: Date.now(),
      },
      createdAt: now,
      updatedAt: now,
    };

    return {
      header,
      dek: activeDek,
      recoveryKeyFormatted,
      kdfEngine: derived.engine,
    };
  } finally {
    zeroize(passwordKekBytes, recoveryKeyBytes);
  }
}

export async function unwrapDekWithPassword(header, masterPassword, opts = {}) {
  const pwWrapper = header?.wrappers?.password;
  if (!pwWrapper?.salt || !pwWrapper?.iv || !pwWrapper?.wrappedDek) {
    throw new KhaznaError(
      'CORRUPT_HEADER',
      'ترويسة الخزنة تالفة أو غير مكتملة.',
      'Vault header is missing password wrapper.'
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
      'password',
      Boolean(opts.extractable)
    );
    return { dek, kdfEngine: derived.engine };
  } catch (err) {
    if (err instanceof KhaznaError) throw err;
    throw new KhaznaError(
      'WRONG_PASSWORD',
      'كلمة المرور الرئيسية غير صحيحة.',
      'Incorrect master password.',
      err
    );
  } finally {
    zeroize(kekBytes);
  }
}

export async function unwrapDekWithRecoveryKey(header, formattedRecoveryKey, opts = {}) {
  const recWrapper = header?.wrappers?.recovery;
  if (!recWrapper?.salt || !recWrapper?.iv || !recWrapper?.wrappedDek) {
    throw new KhaznaError(
      'NO_RECOVERY_WRAPPER',
      'لا يوجد مفتاح استرداد مهيّأ لهذه الخزنة.',
      'No recovery wrapper configured for this vault.'
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
      'recovery',
      Boolean(opts.extractable)
    );
  } catch (err) {
    if (err instanceof KhaznaError) throw err;
    throw new KhaznaError(
      'WRONG_RECOVERY_KEY',
      'مفتاح الاسترداد لا يطابق هذه الخزنة.',
      'Recovery key does not match this vault.',
      err
    );
  } finally {
    zeroize(recoveryKeyBytes);
  }
}

export async function createWebAuthnPrfWrapper(header, extractableDek, prfOutput, meta) {
  const hkdfSalt = randomBytes(16);
  try {
    const kek = await deriveHkdfWrapKey(prfOutput, hkdfSalt, HKDF_INFO_WEBAUTHN);
    const wrapped = await wrapDek(extractableDek, kek, header.vaultId, 'webauthn');
    return {
      mode: 'prf',
      credentialId: meta.credentialId,
      prfSalt: meta.prfSaltB64,
      hkdfSalt: bytesToBase64(hkdfSalt),
      iv: wrapped.iv,
      wrappedDek: wrapped.wrappedDek,
      createdAt: new Date().toISOString(),
    };
  } finally {
    zeroize(hkdfSalt);
  }
}

export async function unwrapDekWithWebAuthnPrf(header, prfOutput, opts = {}) {
  const wa = header?.wrappers?.webauthn;
  if (!wa || wa.mode !== 'prf' || !wa.hkdfSalt || !wa.iv || !wa.wrappedDek) {
    throw new KhaznaError(
      'NO_WEBAUTHN_PRF',
      'فتح البصمة المشفّر (PRF) غير مفعّل لهذه الخزنة.',
      'WebAuthn PRF biometric wrapper is not configured.'
    );
  }
  const hkdfSalt = base64ToBytes(wa.hkdfSalt);
  try {
    const kek = await deriveHkdfWrapKey(prfOutput, hkdfSalt, HKDF_INFO_WEBAUTHN);
    return await unwrapDek(wa, kek, header.vaultId, 'webauthn', Boolean(opts.extractable));
  } catch (err) {
    if (err instanceof KhaznaError) throw err;
    throw new KhaznaError(
      'WEBAUTHN_UNWRAP_FAILED',
      'فشل فك تشفير الخزنة باستخدام البصمة — استخدم كلمة المرور الرئيسية.',
      'Failed to unwrap vault key with WebAuthn PRF output.',
      err
    );
  }
}

export async function rewrapMasterPassword({
  header,
  currentPassword,
  recoveryKey,
  newMasterPassword,
  newKdfSpec,
  enforceMinimums = true,
  useWorker = true,
}) {
  validateMasterPasswordPolicy(newMasterPassword);
  const targetKdf = newKdfSpec || { kdf: header.kdf, params: header.kdfParams };
  validateKdfSpec(targetKdf, enforceMinimums);

  let tempDek = null;
  if (typeof currentPassword === 'string' && currentPassword.length > 0) {
    const res = await unwrapDekWithPassword(header, currentPassword, {
      extractable: true,
      useWorker,
    });
    tempDek = res.dek;
  } else if (typeof recoveryKey === 'string' && recoveryKey.length > 0) {
    tempDek = await unwrapDekWithRecoveryKey(header, recoveryKey, { extractable: true });
  } else {
    throw new KhaznaError(
      'AUTH_REQUIRED',
      'يجب تأكيد هويتك بكلمة المرور الحالية أو مفتاح الاسترداد أولاً.',
      'Current password or recovery key is required to change master password.'
    );
  }

  const newSalt = randomBytes(16);
  let newKekBytes = null;
  try {
    const derived = await deriveKeyBytes(newMasterPassword, newSalt, targetKdf, { useWorker });
    newKekBytes = derived.keyBytes;
    const newKek = await importAesWrapKey(newKekBytes);
    const wrapped = await wrapDek(tempDek, newKek, header.vaultId, 'password');

    const activeDek = await unwrapDek(wrapped, newKek, header.vaultId, 'password', false);
    const now = new Date().toISOString();

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
          updatedAt: now,
        },
      },
      security: {
        ...header.security,
        failedAttempts: 0,
        lockoutUntil: 0,
        lastMasterUnlockAt: Date.now(),
      },
      updatedAt: now,
    };

    return { updatedHeader, dek: activeDek, kdfEngine: derived.engine };
  } finally {
    tempDek = null;
    zeroize(newKekBytes);
  }
}

export async function rotateRecoveryKey({ header, masterPassword, useWorker = true }) {
  const { dek: tempDek } = await unwrapDekWithPassword(header, masterPassword, {
    extractable: true,
    useWorker,
  });

  const recoveryKeyBytes = randomBytes(32);
  const recoverySalt = randomBytes(16);
  try {
    const recoveryKek = await deriveHkdfWrapKey(recoveryKeyBytes, recoverySalt, HKDF_INFO_RECOVERY);
    const wrapped = await wrapDek(tempDek, recoveryKek, header.vaultId, 'recovery');
    const recoveryKeyFormatted = await encodeRecoveryKey(recoveryKeyBytes);
    const now = new Date().toISOString();

    const updatedHeader = {
      ...header,
      wrappers: {
        ...header.wrappers,
        recovery: {
          salt: bytesToBase64(recoverySalt),
          iv: wrapped.iv,
          wrappedDek: wrapped.wrappedDek,
          createdAt: now,
        },
      },
      updatedAt: now,
    };
    return { updatedHeader, recoveryKeyFormatted };
  } finally {
    zeroize(recoveryKeyBytes);
  }
}

export async function encryptRecord(
  dek,
  {
    id,
    type,
    vaultId,
    data,
    schemaVersion = RECORD_SCHEMA_VERSION,
    deletedAt = null,
    createdAt,
    updatedAt,
  }
) {
  if (!dek) {
    throw new KhaznaError('VAULT_LOCKED', 'الخزنة مقفلة حالياً.', 'Vault is locked.');
  }
  const now = new Date().toISOString();
  const iv = randomBytes(12);
  const additionalData = buildAAD({ id, type, schemaVersion, vaultId });
  const plaintext = utf8Encode(JSON.stringify(data));

  try {
    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData },
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
      deletedAt: deletedAt ?? null,
    };
  } finally {
    zeroize(plaintext);
  }
}

export async function decryptRecord(dek, envelope, vaultId) {
  if (!dek) {
    throw new KhaznaError('VAULT_LOCKED', 'الخزنة مقفلة حالياً.', 'Vault is locked.');
  }
  if (!envelope || !envelope.id || !envelope.type || !envelope.iv || !envelope.ct) {
    throw new KhaznaError(
      'CORRUPT_RECORD',
      'أحد السجلات المشفّرة تالف أو ناقص البيانات.',
      'Encrypted record envelope is malformed.'
    );
  }

  const schemaVersion = envelope.schemaVersion ?? RECORD_SCHEMA_VERSION;
  const iv = base64ToBytes(envelope.iv);
  const ct = base64ToBytes(envelope.ct);
  const additionalData = buildAAD({
    id: envelope.id,
    type: envelope.type,
    schemaVersion,
    vaultId,
  });

  let decryptedBuf;
  try {
    decryptedBuf = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData },
      dek,
      ct
    );
  } catch (err) {
    throw new KhaznaError(
      'TAMPER_OR_CORRUPT',
      'فشل التحقق من سلامة السجل المشفّر — قد يكون تالفاً أو تم التلاعب به أو المفتاح خاطئ.',
      'AES-GCM authentication failed: record tampered, corrupted, or wrong key.',
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
      data,
    };
  } catch (err) {
    throw new KhaznaError(
      'CORRUPT_PAYLOAD',
      'تعذّر قراءة محتوى السجل بعد فك التشفير.',
      'Decrypted record JSON payload is corrupted.',
      err
    );
  } finally {
    zeroize(plainBytes);
  }
}

export async function encryptVaultBackup(payload, backupPassword, kdfSpec, opts = {}) {
  if (typeof backupPassword !== 'string' || backupPassword.length < 8) {
    throw new KhaznaError(
      'WEAK_BACKUP_PASSWORD',
      'يجب ألا تقل كلمة مرور النسخة الاحتياطية عن ٨ أحرف (ويُفضّل ١٢ حرفاً فأكثر).',
      'Backup password must be at least 8 characters.'
    );
  }
  validateKdfSpec(kdfSpec, opts.enforceMinimums ?? true);

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const additionalData = buildAAD({
    id: 'backup',
    type: BACKUP_FORMAT_ID,
    schemaVersion: BACKUP_FORMAT_VERSION,
    vaultId: 'khazna-backup',
  });

  let keyBytes = null;
  const plainBytes = utf8Encode(JSON.stringify(payload));
  try {
    const derived = await deriveKeyBytes(backupPassword, salt, kdfSpec, {
      useWorker: opts.useWorker,
    });
    keyBytes = derived.keyBytes;
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const ct = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData },
      key,
      plainBytes
    );

    const envelope = {
      format: BACKUP_FORMAT_ID,
      version: BACKUP_FORMAT_VERSION,
      createdAt: new Date().toISOString(),
      kdf: kdfSpec.kdf,
      kdfParams: { ...kdfSpec.params },
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ct: bytesToBase64(new Uint8Array(ct)),
    };
    return JSON.stringify(envelope, null, 2);
  } finally {
    zeroize(keyBytes, plainBytes);
  }
}

export async function decryptVaultBackup(rawText, backupPassword, opts = {}) {
  let envelope;
  try {
    envelope = JSON.parse(rawText);
  } catch (err) {
    throw new KhaznaError(
      'INVALID_VAULT_FILE',
      'ملف النسخة الاحتياطية (.vault) ليس بصيغة JSON صالحة.',
      'Invalid .vault backup JSON format.',
      err
    );
  }

  if (
    !envelope ||
    envelope.format !== BACKUP_FORMAT_ID ||
    envelope.version !== BACKUP_FORMAT_VERSION ||
    !envelope.salt ||
    !envelope.iv ||
    !envelope.ct
  ) {
    throw new KhaznaError(
      'UNSUPPORTED_VAULT_FILE',
      'صيغة ملف .vault غير مدعومة أو تالفة.',
      'Unsupported or corrupted .vault backup file.'
    );
  }

  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const ct = base64ToBytes(envelope.ct);
  const additionalData = buildAAD({
    id: 'backup',
    type: BACKUP_FORMAT_ID,
    schemaVersion: envelope.version,
    vaultId: 'khazna-backup',
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
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const decrypted = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData },
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
        kdf: envelope.kdf,
      },
    };
  } catch (err) {
    if (err instanceof KhaznaError) throw err;
    throw new KhaznaError(
      'BACKUP_DECRYPT_FAILED',
      'تعذّر فك تشفير ملف .vault — تأكد من صحة كلمة مرور النسخة الاحتياطية أو سلامة الملف.',
      'Failed to decrypt .vault backup (wrong password or tampered file).',
      err
    );
  } finally {
    zeroize(keyBytes, plainBytes);
  }
}

export function generatePassword({
  length = 20,
  lower = true,
  upper = true,
  digits = true,
  symbols = true,
  excludeLookalikes = false,
} = {}) {
  const safeLen = Math.min(128, Math.max(8, Math.floor(length)));
  const activePools = [];
  const filterPool = (s) => (excludeLookalikes ? s.replace(CHARSETS.lookalikes, '') : s);

  if (lower) activePools.push(filterPool(CHARSETS.lower));
  if (upper) activePools.push(filterPool(CHARSETS.upper));
  if (digits) activePools.push(filterPool(CHARSETS.digits));
  if (symbols) activePools.push(filterPool(CHARSETS.symbols));

  const validPools = activePools.filter((p) => p.length > 0);
  if (validPools.length === 0) {
    throw new KhaznaError(
      'NO_CHARSET_SELECTED',
      'اختر مجموعة أحرف واحدة على الأقل لتوليد كلمة المرور.',
      'Select at least one character set.'
    );
  }

  const combined = validPools.join('');
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

  return chars.join('');
}

export function generatePassphrase({
  wordCount = 6,
  separator = '-',
  capitalize = true,
  includeNumber = true,
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

export function evaluatePasswordStrength(password) {
  const pwd = String(password || '');
  const len = Array.from(pwd).length;
  if (len === 0) {
    return {
      score: 0,
      entropyBits: 0,
      labelAr: 'فارغة',
      labelEn: 'Empty',
      feedbackAr: 'أدخل كلمة مرور.',
      feedbackEn: 'Enter a password.',
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
    { ar: 'ضعيفة جداً', en: 'Very weak', fbAr: 'قصيرة جداً أو يسهل تخمينها.', fbEn: 'Too short or predictable.' },
    { ar: 'ضعيفة', en: 'Weak', fbAr: 'زِد الطول ونوّع بين الأحرف والأرقام والرموز.', fbEn: 'Increase length and mix character types.' },
    { ar: 'متوسطة', en: 'Fair', fbAr: 'مقبولة، ويُفضّل زيادتها إلى ١٤ حرفاً فأكثر.', fbEn: 'Decent, aim for 14+ characters.' },
    { ar: 'قوية', en: 'Strong', fbAr: 'كلمة مرور جيدة ومقاومة للتخمين.', fbEn: 'Strong password.' },
    { ar: 'قوية جداً', en: 'Very strong', fbAr: 'ممتازة وعالية الإنتروبيا.', fbEn: 'Excellent high-entropy password.' },
  ];

  const meta = labels[score];
  return {
    score,
    entropyBits,
    labelAr: meta.ar,
    labelEn: meta.en,
    feedbackAr: meta.fbAr,
    feedbackEn: meta.fbEn,
  };
}

export const DEFAULT_FALLBACK_KDF_SPEC = Object.freeze({
  kdf: KDF_ALGO.PBKDF2_SHA256,
  params: { iterations: 600000 },
});
