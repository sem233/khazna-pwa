/**
 * Khazna Reliability & Storage Layer
 *
 * - IndexedDB with schema versioning + forward migrations
 * - Zero-dependency in-memory adapter fallback (used automatically in Node.js automated tests)
 * - Web Locks API write serialization (prevents concurrent multi-tab corruption)
 * - BroadcastChannel cross-tab sync (lock state, vault updates, wipe notifications)
 * - navigator.storage.persist() + quota monitoring & graceful QuotaExceededError handling
 * - Rolling encrypted snapshots (never plaintext!) before every destructive operation
 * - Vault Health Check verifying every record decrypts cleanly with AAD authentication
 */

import { decryptRecord } from '../crypto/vault-crypto.js';
import { KhaznaError, randomId } from '../crypto/utils.js';

export const DB_NAME = 'khazna_vault_db';
export const DB_VERSION = 1;
export const MAX_SNAPSHOTS = 5;

export const STORES = Object.freeze({
  META: 'meta',
  RECORDS: 'records',
  SNAPSHOTS: 'snapshots',
});

export const DEFAULT_SETTINGS = Object.freeze({
  lang: 'ar',
  theme: 'dark',
  autoLockSec: 120,
  bgGraceSec: 15,
  clipboardClearSec: 30,
  copyComboMode: 'two-step',
  reauthSensitive: true,
  lowEndBlur: 'auto',
  lastBackupAt: null,
  backupReminderDays: 7,
  lastHealthCheck: null,
  onboardingDone: false,
});

function structuredCloneSafe(val) {
  if (typeof structuredClone === 'function') return structuredClone(val);
  return JSON.parse(JSON.stringify(val));
}

function normalizeQuotaError(err) {
  if (
    err?.name === 'QuotaExceededError' ||
    err?.code === 22 ||
    /quota/i.test(String(err?.message || ''))
  ) {
    return new KhaznaError(
      'STORAGE_QUOTA_EXCEEDED',
      'مساحة التخزين على جهازك ممتلئة. احذف بعض اللقطات القديمة أو فرّغ مساحة ثم حاول مجدداً.',
      'Device storage quota exceeded. Free space or clear old snapshots and retry.',
      err
    );
  }
  return err;
}

export function createMemoryBackend() {
  const stores = {
    [STORES.META]: new Map(),
    [STORES.RECORDS]: new Map(),
    [STORES.SNAPSHOTS]: new Map(),
  };

  return {
    kind: 'memory',
    async transaction(storeNames, mode, fn) {
      const backup = mode === 'readwrite'
        ? Object.fromEntries(
            storeNames.map((name) => [
              name,
              new Map(Array.from(stores[name].entries(), ([k, v]) => [k, structuredCloneSafe(v)])),
            ])
          )
        : null;

      const txApi = {
        get: async (store, key) => {
          const val = stores[store].get(key);
          return val === undefined ? undefined : structuredCloneSafe(val);
        },
        getAll: async (store) => {
          return Array.from(stores[store].values(), (v) => structuredCloneSafe(v));
        },
        put: async (store, value, key) => {
          const k = key !== undefined ? key : (value.key ?? value.id);
          stores[store].set(k, structuredCloneSafe(value));
        },
        delete: async (store, key) => {
          stores[store].delete(key);
        },
        clear: async (store) => {
          stores[store].clear();
        },
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
    async close() {},
  };
}

export function createIndexedDbBackend(dbName = DB_NAME) {
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
            db.createObjectStore(STORES.META, { keyPath: 'key' });
          }
          if (!db.objectStoreNames.contains(STORES.RECORDS)) {
            const recStore = db.createObjectStore(STORES.RECORDS, { keyPath: 'id' });
            recStore.createIndex('by_type', 'type', { unique: false });
            recStore.createIndex('by_updatedAt', 'updatedAt', { unique: false });
          }
          if (!db.objectStoreNames.contains(STORES.SNAPSHOTS)) {
            const snapStore = db.createObjectStore(STORES.SNAPSHOTS, { keyPath: 'id' });
            snapStore.createIndex('by_createdAt', 'createdAt', { unique: false });
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
          'IDB_OPEN_FAILED',
          'تعذّر فتح قاعدة البيانات المحلية (IndexedDB). تأكد من عدم تفعيل التصفح الخفي المقيّد.',
          'Failed to open IndexedDB database.',
          req.error
        ));
      };

      req.onblocked = () => {
        reject(new KhaznaError(
          'IDB_BLOCKED',
          'قاعدة البيانات مفتوحة في تبويب آخر — أغلِق التبويبات الأخرى ثم أعد المحاولة.',
          'IndexedDB upgrade blocked by another open tab.'
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
    kind: 'indexeddb',
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
          clear: (store) => reqToPromise(tx.objectStore(store).clear()),
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
          reject(normalizeQuotaError(fnError || tx.error || new Error('Transaction aborted')));
        };

        Promise.resolve()
          .then(() => fn(txApi))
          .then((res) => {
            fnResult = res;
          })
          .catch((err) => {
            fnError = err;
            try {
              tx.abort();
            } catch {
              // ignore
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
    },
  };
}

export class VaultStorage {
  constructor(opts = {}) {
    this.backend = opts.backend || (
      typeof globalThis.indexedDB !== 'undefined'
        ? createIndexedDbBackend(DB_NAME)
        : createMemoryBackend()
    );
    this.lockName = opts.lockName || 'khazna-vault-write-lock';
    this.tabId = randomId('tab');
    this._localQueue = Promise.resolve();
    this._listeners = new Set();

    if (typeof globalThis.BroadcastChannel === 'function') {
      try {
        this._channel = new BroadcastChannel(opts.channelName || 'khazna-vault-sync');
        this._channel.onmessage = (ev) => {
          const msg = ev.data;
          if (!msg || msg.tabId === this.tabId) return;
          for (const cb of this._listeners) {
            try {
              cb(msg);
            } catch {
              // Isolate subscriber errors
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
      // Ignore closed channel
    }
  }

  async close() {
    if (this._channel) {
      try {
        this._channel.close();
      } catch {
        // ignore
      }
      this._channel = null;
    }
    if (this.backend && typeof this.backend.close === 'function') {
      await this.backend.close();
    }
  }

  async withWriteLock(fn) {
    const isOpaqueOrigin =
      typeof globalThis.location !== 'undefined' &&
      (globalThis.location.protocol === 'file:' || globalThis.location.origin === 'null');

    if (!isOpaqueOrigin && typeof globalThis.navigator?.locks?.request === 'function') {
      try {
        return await globalThis.navigator.locks.request(this.lockName, { mode: 'exclusive' }, fn);
      } catch (err) {
        if (err?.name !== 'SecurityError' && err?.name !== 'NotSupportedError') {
          throw err;
        }
        // Fall through to in-tab queue when LockManager rejects opaque/restricted origins.
      }
    }
    const prev = this._localQueue;
    let release;
    this._localQueue = new Promise((r) => { release = r; });
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
      if (typeof globalThis.navigator?.storage?.persisted === 'function') {
        persisted = await globalThis.navigator.storage.persisted();
      }
      if (!persisted && typeof globalThis.navigator?.storage?.persist === 'function') {
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
      if (knownPersisted === undefined && typeof globalThis.navigator?.storage?.persisted === 'function') {
        persisted = await globalThis.navigator.storage.persisted();
      }
      if (typeof globalThis.navigator?.storage?.estimate === 'function') {
        const est = await globalThis.navigator.storage.estimate();
        usageBytes = est.usage ?? 0;
        quotaBytes = est.quota ?? 0;
      }
    } catch {
      // Ignore unsupported storage manager APIs
    }
    const percentUsed = quotaBytes > 0 ? Math.min(100, Number(((usageBytes / quotaBytes) * 100).toFixed(2))) : 0;
    return { persisted, usageBytes, quotaBytes, percentUsed };
  }

  async getHeader() {
    return this.backend.transaction([STORES.META], 'readonly', async (tx) => {
      const row = await tx.get(STORES.META, 'header');
      return row ? row.value : null;
    });
  }

  async hasVault() {
    const header = await this.getHeader();
    return Boolean(header && header.vaultId);
  }

  async saveHeader(header) {
    return this.withWriteLock(async () => {
      await this.backend.transaction([STORES.META], 'readwrite', async (tx) => {
        await tx.put(STORES.META, { key: 'header', value: header });
      });
      this.broadcast('VAULT_UPDATED', { scope: 'header' });
    });
  }

  async getSettings() {
    const saved = await this.backend.transaction([STORES.META], 'readonly', async (tx) => {
      const row = await tx.get(STORES.META, 'settings');
      return row ? row.value : null;
    });
    return { ...DEFAULT_SETTINGS, ...(saved || {}) };
  }

  async saveSettings(partial) {
    return this.withWriteLock(async () => {
      const merged = await this.backend.transaction([STORES.META], 'readwrite', async (tx) => {
        const existing = (await tx.get(STORES.META, 'settings'))?.value || {};
        const next = { ...DEFAULT_SETTINGS, ...existing, ...partial };
        await tx.put(STORES.META, { key: 'settings', value: next });
        return next;
      });
      this.broadcast('VAULT_UPDATED', { scope: 'settings' });
      return merged;
    });
  }

  async getRecord(id) {
    return this.backend.transaction([STORES.RECORDS], 'readonly', (tx) =>
      tx.get(STORES.RECORDS, id)
    );
  }

  async getAllRecords(type = null) {
    const all = await this.backend.transaction([STORES.RECORDS], 'readonly', (tx) =>
      tx.getAll(STORES.RECORDS)
    );
    return type ? all.filter((r) => r.type === type) : all;
  }

  async putRecord(envelope) {
    return this.withWriteLock(async () => {
      await this.backend.transaction([STORES.RECORDS], 'readwrite', async (tx) => {
        await tx.put(STORES.RECORDS, envelope);
      });
      this.broadcast('VAULT_UPDATED', { scope: 'record', id: envelope.id });
    });
  }

  async putRecordsBatch(envelopes) {
    if (!envelopes.length) return;
    return this.withWriteLock(async () => {
      await this.backend.transaction([STORES.RECORDS], 'readwrite', async (tx) => {
        for (const env of envelopes) {
          await tx.put(STORES.RECORDS, env);
        }
      });
      this.broadcast('VAULT_UPDATED', { scope: 'batch', count: envelopes.length });
    });
  }

  async deleteRecord(id) {
    return this.withWriteLock(async () => {
      await this.backend.transaction([STORES.RECORDS], 'readwrite', async (tx) => {
        await tx.delete(STORES.RECORDS, id);
      });
      this.broadcast('VAULT_UPDATED', { scope: 'delete', id });
    });
  }

  async deleteRecordsBatch(ids) {
    if (!ids.length) return;
    return this.withWriteLock(async () => {
      await this.backend.transaction([STORES.RECORDS], 'readwrite', async (tx) => {
        for (const id of ids) {
          await tx.delete(STORES.RECORDS, id);
        }
      });
      this.broadcast('VAULT_UPDATED', { scope: 'batch-delete', count: ids.length });
    });
  }

  async atomicOperationWithSnapshot({
    reason,
    newHeader = null,
    putRecords = [],
    deleteIds = [],
    replaceAllRecords = false,
  }) {
    return this.withWriteLock(async () => {
      const snapshotId = randomId('snap');
      const now = new Date().toISOString();

      await this.backend.transaction(
        [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
        'readwrite',
        async (tx) => {
          const currentHeader = (await tx.get(STORES.META, 'header'))?.value || null;
          const currentRecords = await tx.getAll(STORES.RECORDS);

          if (currentHeader) {
            await tx.put(STORES.SNAPSHOTS, {
              id: snapshotId,
              reason,
              createdAt: now,
              recordCount: currentRecords.length,
              header: currentHeader,
              records: currentRecords,
            });

            const allSnaps = await tx.getAll(STORES.SNAPSHOTS);
            allSnaps.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
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
            await tx.put(STORES.META, { key: 'header', value: newHeader });
          }
        }
      );

      this.broadcast('VAULT_UPDATED', { scope: 'atomic', reason });
      return snapshotId;
    });
  }

  async createSnapshot(reason = 'manual') {
    return this.withWriteLock(async () => {
      const id = randomId('snap');
      const now = new Date().toISOString();
      await this.backend.transaction(
        [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
        'readwrite',
        async (tx) => {
          const header = (await tx.get(STORES.META, 'header'))?.value;
          if (!header) return;
          const records = await tx.getAll(STORES.RECORDS);
          await tx.put(STORES.SNAPSHOTS, {
            id,
            reason,
            createdAt: now,
            recordCount: records.length,
            header,
            records,
          });
          const allSnaps = await tx.getAll(STORES.SNAPSHOTS);
          allSnaps.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
          for (let i = MAX_SNAPSHOTS; i < allSnaps.length; i++) {
            await tx.delete(STORES.SNAPSHOTS, allSnaps[i].id);
          }
        }
      );
      return id;
    });
  }

  async listSnapshots() {
    const snaps = await this.backend.transaction([STORES.SNAPSHOTS], 'readonly', (tx) =>
      tx.getAll(STORES.SNAPSHOTS)
    );
    return snaps
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((s) => ({
        id: s.id,
        reason: s.reason,
        createdAt: s.createdAt,
        recordCount: s.recordCount,
      }));
  }

  async restoreSnapshot(snapshotId) {
    return this.withWriteLock(async () => {
      await this.backend.transaction(
        [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
        'readwrite',
        async (tx) => {
          const target = await tx.get(STORES.SNAPSHOTS, snapshotId);
          if (!target) {
            throw new KhaznaError(
              'SNAPSHOT_NOT_FOUND',
              'اللقطة الاحتياطية المطلوبة غير موجودة.',
              'Requested encrypted snapshot was not found.'
            );
          }

          const currentHeader = (await tx.get(STORES.META, 'header'))?.value;
          const currentRecords = await tx.getAll(STORES.RECORDS);
          if (currentHeader) {
            await tx.put(STORES.SNAPSHOTS, {
              id: randomId('snap'),
              reason: 'pre-restore',
              createdAt: new Date().toISOString(),
              recordCount: currentRecords.length,
              header: currentHeader,
              records: currentRecords,
            });
          }

          await tx.put(STORES.META, { key: 'header', value: target.header });
          await tx.clear(STORES.RECORDS);
          for (const rec of target.records) {
            await tx.put(STORES.RECORDS, rec);
          }

          const allSnaps = await tx.getAll(STORES.SNAPSHOTS);
          allSnaps.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
          for (let i = MAX_SNAPSHOTS; i < allSnaps.length; i++) {
            await tx.delete(STORES.SNAPSHOTS, allSnaps[i].id);
          }
        }
      );
      this.broadcast('VAULT_UPDATED', { scope: 'restore-snapshot', snapshotId });
    });
  }

  async purgeExpiredTrash(days = 30) {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const all = await this.getAllRecords();
    const expiredIds = all
      .filter((r) => r.deletedAt && Date.parse(r.deletedAt) < cutoff)
      .map((r) => r.id);

    if (expiredIds.length > 0) {
      await this.deleteRecordsBatch(expiredIds);
    }
    return expiredIds.length;
  }

  async runVaultHealthCheck(dek) {
    const header = await this.getHeader();
    if (!header) {
      throw new KhaznaError('NO_VAULT', 'لا توجد خزنة مهيّأة.', 'No vault initialized.');
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
          id: env?.id || 'unknown',
          type: env?.type || 'unknown',
          code: err?.code || 'DECRYPT_FAILED',
        });
      }
    }

    const report = {
      ok: corrupted.length === 0,
      total: envelopes.length,
      valid,
      corrupted,
      estimatedBytes,
      checkedAt: new Date().toISOString(),
    };

    await this.saveSettings({
      lastHealthCheck: {
        ok: report.ok,
        total: report.total,
        corruptedCount: corrupted.length,
        checkedAt: report.checkedAt,
      },
    });

    return report;
  }

  async wipeAll({ wipeSettings = false } = {}) {
    return this.withWriteLock(async () => {
      await this.backend.transaction(
        [STORES.META, STORES.RECORDS, STORES.SNAPSHOTS],
        'readwrite',
        async (tx) => {
          const settingsRow = wipeSettings ? null : await tx.get(STORES.META, 'settings');
          await tx.clear(STORES.META);
          await tx.clear(STORES.RECORDS);
          await tx.clear(STORES.SNAPSHOTS);
          if (settingsRow) {
            await tx.put(STORES.META, {
              key: 'settings',
              value: { ...settingsRow.value, onboardingDone: false, lastBackupAt: null },
            });
          }
        }
      );
      this.broadcast('VAULT_WIPED');
    });
  }

  async close() {
    if (this._channel) {
      this._channel.close();
      this._channel = null;
    }
    await this.backend.close();
  }
}
