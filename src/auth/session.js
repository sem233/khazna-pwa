/**
 * Khazna Vault Session & Security Controller
 *
 * - Keeps the active DEK strictly in a private class field (#dek), NEVER global or persisted.
 * - Enforces exponential back-off after failed unlock attempts + optional wipe-after-N-failures.
 * - Manages inactivity auto-lock (30s - 15m), background/screen-off grace timer, privacy blur,
 *   and cross-tab lock synchronization via BroadcastChannel.
 * - Provides best-effort Clipboard auto-clear guard with honest platform-limit reporting.
 */

import { calibrateKdf } from '../crypto/kdf.js';
import {
  createVaultCrypto,
  decryptRecord,
  encryptRecord,
  rewrapMasterPassword,
  rotateRecoveryKey,
  unwrapDekWithPassword,
  unwrapDekWithRecoveryKey,
} from '../crypto/vault-crypto.js';
import { KhaznaError, randomId } from '../crypto/utils.js';
import {
  armConvenienceRamSession,
  clearConvenienceRamSession,
  enrollBiometric,
  getConvenienceStatus,
  unlockWithBiometric,
  verifyBiometricForReauth,
} from './webauthn.js';

const BACKOFF_SCHEDULE_SEC = Object.freeze([0, 0, 0, 5, 15, 30, 60, 120, 300, 600]);

export function computeBackoffMs(failedAttempts) {
  if (failedAttempts <= 0) return 0;
  const idx = Math.min(failedAttempts - 1, BACKOFF_SCHEDULE_SEC.length - 1);
  return BACKOFF_SCHEDULE_SEC[idx] * 1000;
}

export const DEFAULT_SECTIONS = Object.freeze([
  { nameAr: 'عام', nameEn: 'General', emoji: '🔐', color: '#38bdf8' },
  { nameAr: 'البنوك والمال', nameEn: 'Banking', emoji: '🏦', color: '#10b981' },
  { nameAr: 'التواصل الاجتماعي', nameEn: 'Social', emoji: '💬', color: '#a78bfa' },
  { nameAr: 'العمل', nameEn: 'Work', emoji: '💼', color: '#f59e0b' },
]);

export class ClipboardGuard {
  constructor(env = globalThis) {
    this._env = env;
    this._timer = null;
    this._listeners = new Set();
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
        // isolate subscriber errors
      }
    }
  }

  async copySecret(text, clearAfterSec = 30) {
    const clip = this._env.navigator?.clipboard;
    if (!clip || typeof clip.writeText !== 'function') {
      throw new KhaznaError(
        'CLIPBOARD_UNAVAILABLE',
        'تعذّر الوصول إلى الحافظة في هذا المتصفح.',
        'Clipboard API is unavailable.'
      );
    }

    await clip.writeText(String(text));

    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }

    if (clearAfterSec > 0) {
      const clearAt = Date.now() + clearAfterSec * 1000;
      this._emit({ type: 'copied', clearAfterSec, clearAt });

      this._timer = setTimeout(async () => {
        this._timer = null;
        try {
          if (
            this._env.document &&
            typeof this._env.document.hasFocus === 'function' &&
            !this._env.document.hasFocus()
          ) {
            this._emit({ type: 'clear-skipped-unfocused' });
            return;
          }
          await clip.writeText('');
          this._emit({ type: 'cleared' });
        } catch {
          this._emit({ type: 'clear-failed' });
        }
      }, clearAfterSec * 1000);
    } else {
      this._emit({ type: 'copied', clearAfterSec: 0, clearAt: 0 });
    }
  }

  cancel() {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }
}

export class VaultSession {
  /** @type {CryptoKey|null} Strictly private non-extractable DEK */
  #dek = null;

  constructor({ storage, nowFn = () => Date.now(), env = globalThis, useWorker = true }) {
    this.storage = storage;
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
    this._listeners = new Set();
    this.clipboard = new ClipboardGuard(env);

    this._unsubSync = this.storage.onSyncEvent((msg) => {
      if (msg.type === 'VAULT_LOCKED') {
        this.lock({ broadcast: false, reason: 'cross-tab' });
      } else if (msg.type === 'VAULT_WIPED') {
        clearConvenienceRamSession();
        this.lock({ broadcast: false, reason: 'wiped' });
        this._header = null;
        this._emit('wiped', {});
      } else if (msg.type === 'VAULT_UPDATED') {
        this.refreshMeta().then(() => this._emit('sync-updated', msg.detail));
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
        // isolate UI subscriber errors
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
      header: this._header,
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
    const wa = this._header?.wrappers?.webauthn;
    if (!wa) return { enabled: false, mode: null, ready: false, reason: 'disabled' };
    if (wa.mode === 'prf') {
      return { enabled: true, mode: 'prf', ready: true, reason: 'prf-ready' };
    }
    const conv = getConvenienceStatus(this._header, this._now());
    return { enabled: true, mode: 'convenience', ready: conv.ready, reason: conv.reason, remainingMs: conv.remainingMs || 0 };
  }

  _assertUnlocked() {
    if (!this.#dek || !this._header) {
      throw new KhaznaError('VAULT_LOCKED', 'الخزنة مقفلة حالياً.', 'Vault is locked.');
    }
  }

  _assertNotLockedOut() {
    const rem = this.getLockoutRemainingMs();
    if (rem > 0) {
      const secs = Math.ceil(rem / 1000);
      throw new KhaznaError(
        'LOCKED_OUT',
        `تم تقييد المحاولات مؤقتاً لأمانك. حاول مجدداً بعد ${secs} ثانية.`,
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
      clearConvenienceRamSession();
      this.#dek = null;
      await this.storage.wipeAll({ wipeSettings: false });
      this._header = null;
      this._emit('wiped', { reason: 'max-failures' });
      throw new KhaznaError(
        'VAULT_WIPED_AFTER_FAILURES',
        `تم مسح الخزنة تلقائياً بعد ${failedAttempts} محاولات فاشلة متتالية وفقاً لإعدادات الأمان.`,
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
        lockoutUntil,
      },
    };
    this._header = updatedHeader;
    await this.storage.saveHeader(updatedHeader);
    this._emit('failed-attempt', { failedAttempts, lockoutUntil, backoffMs });
  }

  async _resetFailedAttempts(markMasterUnlock = false) {
    if (!this._header) return;
    const prev = this._header.security || {};
    const needsSave =
      (prev.failedAttempts || 0) > 0 ||
      (prev.lockoutUntil || 0) > 0 ||
      markMasterUnlock;
    if (!needsSave) return;

    const updatedHeader = {
      ...this._header,
      security: {
        ...prev,
        failedAttempts: 0,
        lockoutUntil: 0,
        lastMasterUnlockAt: markMasterUnlock ? this._now() : (prev.lastMasterUnlockAt || this._now()),
      },
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
      useWorker: this._useWorker,
    });

    await this.storage.saveHeader(header);
    this._header = header;
    this.#dek = dek;
    this._unlockedAt = this._now();
    this._lastActivityAt = this._now();

    if (seedDefaultSections) {
      const lang = this._settings?.lang || 'ar';
      const envelopes = [];
      for (let i = 0; i < DEFAULT_SECTIONS.length; i++) {
        const s = DEFAULT_SECTIONS[i];
        envelopes.push(await encryptRecord(this.#dek, {
          id: randomId('sec'),
          type: 'section',
          vaultId: header.vaultId,
          data: {
            name: lang === 'en' ? s.nameEn : s.nameAr,
            emoji: s.emoji,
            color: s.color,
            order: i,
          },
        }));
      }
      await this.storage.putRecordsBatch(envelopes);
    }

    this._settings = await this.storage.saveSettings({ onboardingDone: true });
    this._scheduleInactivityLock();
    this._emit('unlocked', { method: 'create', kdfEngine });

    return {
      header,
      recoveryKeyFormatted,
      kdfEngine,
    };
  }

  /**
   * Unlocks the vault using the Master Password.
   */
  async unlockWithPassword(masterPassword) {
    await this.refreshMeta();
    if (!this._header) {
      throw new KhaznaError('NO_VAULT', 'لا توجد خزنة مهيّأة على هذا الجهاز.', 'No vault exists.');
    }
    this._assertNotLockedOut();

    try {
      const wantConvenienceArm = this._header?.wrappers?.webauthn?.mode === 'convenience';
      const { dek, kdfEngine } = await unwrapDekWithPassword(this._header, masterPassword, {
        extractable: wantConvenienceArm,
        useWorker: this._useWorker,
      });

      if (wantConvenienceArm) {
        await armConvenienceRamSession(this._header.vaultId, dek, this._now());
        // Re-unwrap strictly as non-extractable for session storage
        const strict = await unwrapDekWithPassword(this._header, masterPassword, {
          extractable: false,
          useWorker: this._useWorker,
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
      this._emit('unlocked', { method: 'password', kdfEngine });
      return { kdfEngine };
    } catch (err) {
      if (err?.code === 'WRONG_PASSWORD') {
        await this._recordFailedAttempt();
      }
      throw err;
    }
  }

  /**
   * Unlocks the vault via Android Biometric (WebAuthn PRF or RAM-only Convenience Fallback).
   */
  async unlockWithBiometric(opts = {}) {
    await this.refreshMeta();
    if (!this._header) {
      throw new KhaznaError('NO_VAULT', 'لا توجد خزنة مهيّأة.', 'No vault exists.');
    }
    this._assertNotLockedOut();

    const { dek, mode } = await unlockWithBiometric(this._header, {
      ...opts,
      env: opts.env || this._env,
      now: this._now(),
    });

    this.#dek = dek;
    await this._resetFailedAttempts(false);
    await this.storage.purgeExpiredTrash(30);
    this._unlockedAt = this._now();
    this._lastActivityAt = this._now();
    this._scheduleInactivityLock();
    this._emit('unlocked', { method: `biometric-${mode}` });
    return { mode };
  }

  /**
   * Unlocks the vault using the 14-group Base32 Recovery Key, optionally setting a new Master Password immediately.
   */
  async unlockWithRecoveryKey(formattedRecoveryKey, newMasterPassword = null, opts = {}) {
    await this.refreshMeta();
    if (!this._header) {
      throw new KhaznaError('NO_VAULT', 'لا توجد خزنة مهيّأة.', 'No vault exists.');
    }
    this._assertNotLockedOut();

    try {
      if (newMasterPassword) {
        const { updatedHeader, dek } = await rewrapMasterPassword({
          header: this._header,
          recoveryKey: formattedRecoveryKey,
          newMasterPassword,
          enforceMinimums: opts.enforceMinimums ?? true,
          useWorker: this._useWorker,
        });
        await this.storage.atomicOperationWithSnapshot({
          reason: 'recovery-password-reset',
          newHeader: updatedHeader,
        });
        this._header = updatedHeader;
        this.#dek = dek;
      } else {
        const dek = await unwrapDekWithRecoveryKey(this._header, formattedRecoveryKey, {
          extractable: false,
        });
        this.#dek = dek;
        await this._resetFailedAttempts(true);
      }

      await this.storage.purgeExpiredTrash(30);
      this._unlockedAt = this._now();
      this._lastActivityAt = this._now();
      this._scheduleInactivityLock();
      this._emit('unlocked', { method: 'recovery' });
      return true;
    } catch (err) {
      if (
        err?.code === 'WRONG_RECOVERY_KEY' ||
        err?.code === 'INVALID_RECOVERY_KEY_CHECKSUM' ||
        err?.code === 'INVALID_RECOVERY_KEY'
      ) {
        await this._recordFailedAttempt();
      }
      throw err;
    }
  }

  /**
   * Locks the vault immediately, drops DEK reference, cancels timers, and syncs across tabs.
   */
  lock({ broadcast = true, reason = 'manual', clearConvenience = false } = {}) {
    this.#dek = null;
    this._clearTimers();
    if (clearConvenience) {
      clearConvenienceRamSession();
    }
    if (broadcast) {
      this.storage.broadcast('VAULT_LOCKED', { reason });
    }
    this._emit('locked', { reason });
  }

  /**
   * Re-authenticates the user before sensitive actions (reveal CVV/PIN, plain export,
   * change master password, wipe vault).
   */
  async verifyReauth({ masterPassword = null, useBiometric = false, env = this._env } = {}) {
    this._assertUnlocked();
    if (useBiometric && this._header?.wrappers?.webauthn) {
      await verifyBiometricForReauth(this._header, { env });
      return true;
    }
    if (typeof masterPassword === 'string' && masterPassword.length > 0) {
      await unwrapDekWithPassword(this._header, masterPassword, {
        extractable: false,
        useWorker: this._useWorker,
      });
      return true;
    }
    throw new KhaznaError(
      'REAUTH_REQUIRED',
      'يتطلب هذا الإجراء الحساس تأكيد هويتك بكلمة المرور الرئيسية أو البصمة.',
      'Re-authentication with Master Password or Biometric is required.'
    );
  }

  /**
   * Enrolls WebAuthn biometric unlock (requires Master Password once to unwrap DEK transiently).
   */
  async enrollBiometricWithPassword(masterPassword, opts = {}) {
    this._assertUnlocked();
    const { dek: tempDek } = await unwrapDekWithPassword(this._header, masterPassword, {
      extractable: true,
      useWorker: this._useWorker,
    });

    const result = await enrollBiometric({
      header: this._header,
      extractableDek: tempDek,
      rpId: opts.rpId,
      env: opts.env || this._env,
    });

    if (result.mode === 'prf') {
      const updatedHeader = {
        ...this._header,
        wrappers: {
          ...this._header.wrappers,
          webauthn: result.wrapper,
        },
        updatedAt: new Date().toISOString(),
      };
      await this.storage.saveHeader(updatedHeader);
      this._header = updatedHeader;
      this._emit('biometric-updated', { mode: 'prf' });
      return { mode: 'prf' };
    }

    // PRF unavailable: caller UI must display honest warning and call confirmConvenienceBiometric() if user opts in.
    return {
      ...result,
      _armConvenience: async () => {
        await armConvenienceRamSession(this._header.vaultId, tempDek, this._now());
        const updatedHeader = {
          ...this._header,
          wrappers: {
            ...this._header.wrappers,
            webauthn: result.pendingConvenience,
          },
          updatedAt: new Date().toISOString(),
        };
        await this.storage.saveHeader(updatedHeader);
        this._header = updatedHeader;
        this._emit('biometric-updated', { mode: 'convenience' });
        return { mode: 'convenience' };
      },
    };
  }

  async disableBiometric() {
    this._assertUnlocked();
    clearConvenienceRamSession();
    const updatedHeader = {
      ...this._header,
      wrappers: {
        ...this._header.wrappers,
        webauthn: null,
      },
      updatedAt: new Date().toISOString(),
    };
    await this.storage.saveHeader(updatedHeader);
    this._header = updatedHeader;
    this._emit('biometric-updated', { mode: null });
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
      useWorker: this._useWorker,
    });

    await this.storage.atomicOperationWithSnapshot({
      reason: 'master-password-change',
      newHeader: updatedHeader,
    });
    this._header = updatedHeader;
    this.#dek = dek;
    this._emit('header-updated', { reason: 'master-password-change' });
    return { kdfEngine };
  }

  async rotateRecoveryKeyWithPassword(masterPassword) {
    this._assertUnlocked();
    const { updatedHeader, recoveryKeyFormatted } = await rotateRecoveryKey({
      header: this._header,
      masterPassword,
      useWorker: this._useWorker,
    });
    await this.storage.atomicOperationWithSnapshot({
      reason: 'recovery-key-rotate',
      newHeader: updatedHeader,
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
        wipeAfterFailures: clean,
      },
      updatedAt: new Date().toISOString(),
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
    this._emit('settings-updated', { settings: this._settings });
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
      createdAt: createdAt || existing?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      deletedAt,
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
      data,
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
      updatedAt: new Date().toISOString(),
      deletedAt: new Date().toISOString(),
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
      updatedAt: new Date().toISOString(),
      deletedAt: null,
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
        updatedAt: item.updatedAt || new Date().toISOString(),
        deletedAt: item.deletedAt ?? null,
      }));
    }
    return envelopes;
  }

  async runHealthCheck() {
    this._assertUnlocked();
    return this.storage.runVaultHealthCheck(this.#dek);
  }

  async wipeVault() {
    clearConvenienceRamSession();
    this.lock({ broadcast: false, reason: 'wiped', clearConvenience: true });
    await this.storage.wipeAll({ wipeSettings: false });
    this._header = null;
    this._emit('wiped', { reason: 'manual' });
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
      this.lock({ reason: 'inactivity' });
    }, sec * 1000);
  }

  handleVisibilityChange(hidden) {
    if (hidden) {
      this.setPrivacyBlur(true);
      if (this.isUnlocked) {
        const graceSec = Math.max(0, Math.min(300, this._settings?.bgGraceSec ?? 15));
        if (this._bgTimer) clearTimeout(this._bgTimer);
        if (graceSec === 0) {
          this.lock({ reason: 'background' });
        } else {
          this._bgTimer = setTimeout(() => {
            this.lock({ reason: 'background' });
          }, graceSec * 1000);
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
        if (this._now() - this._lastActivityAt >= autoSec * 1000) {
          this.lock({ reason: 'inactivity' });
        } else {
          this.touchActivity();
        }
      }
    }
  }

  setPrivacyBlur(blurred) {
    if (this._blurred === blurred) return;
    this._blurred = blurred;
    this._emit('privacy-blur', { blurred });
  }

  destroy() {
    this._clearTimers();
    this.clipboard.cancel();
    if (this._unsubSync) this._unsubSync();
    this.#dek = null;
  }
}
