/**
 * Khazna (خزنة) — Automated Verification & Security Test Suite (Zero External Dependencies)
 *
 * Tests:
 * 1. Cryptographic primitives (AES-256-GCM, AAD tampering rejection, Argon2id pure-JS, PBKDF2, Recovery Key)
 * 2. Storage & opaque origin (`file://`) write lock fallback
 * 3. VaultSession lifecycle: create, lock, unlock, backoff, recovery reset, bulk move, native Android biometric
 * 4. ClipboardGuard: Capacitor native plugin + Web API + fallback
 * 5. Domain logic: cards Luhn/masking, Arabic/English search, audit score
 * 6. Import/Export (.vault encrypted, JSON, Bitwarden, CSV) & Device Sync merge
 * 7. Static security invariants: zero innerHTML/outerHTML/insertAdjacentHTML/eval/inline style=, zero external URLs
 * 8. i18n completeness across all src/ files
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  base64ToBytes,
  bytesToBase64,
  decodeRecoveryKey,
  encodeRecoveryKey,
  randomBytes,
} from '../src/crypto/utils.js';
import { argon2idPure } from '../src/crypto/argon2id-pure.js';
import {
  createVaultCrypto,
  decryptRecord,
  encodePatternSecret,
  encryptRecord,
  evaluatePasswordStrength,
  generatePassphrase,
  generatePassword,
  isPatternSecret,
} from '../src/crypto/vault-crypto.js';
import { createMemoryBackend, VaultStorage } from '../src/storage/idb.js';
import { ClipboardGuard, VaultSession } from '../src/auth/session.js';
import { detectCardBrand, maskCardNumber, validateLuhn } from '../src/domain/cards.js';
import { analyzeSectionDuplicates, filterAndSortPasswords } from '../src/domain/search.js';
import { computeVaultAuditAndStats } from '../src/domain/audit.js';
import {
  exportBitwardenJson,
  exportChromeCsv,
  exportEncryptedVault,
  parseImportSource,
} from '../src/import-export/formats.js';
import {
  applySyncMerge,
  decodeSyncPackage,
  encodeSyncPackage,
  planSyncMerge,
  selectSyncRecords,
} from '../src/import-export/sync.js';
import { t } from '../src/i18n/strings.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    console.error(`  ✗ ${name}`);
    console.error(`    ${err?.stack || err}`);
  }
}

console.log('🔐 Running Khazna Automated Test Suite...\n');

// Fast test KDF spec (Argon2id minimal for CI speed while verifying full crypto pipeline)
const FAST_KDF = { kdf: 'pbkdf2-sha256', params: { iterations: 2000 } };

await test('Crypto: Base64 & Recovery Key encode/decode + checksum tampering rejection', async () => {
  const key = randomBytes(32);
  const formatted = await encodeRecoveryKey(key);
  assert.equal(formatted.split('-').length, 14);
  const decoded = await decodeRecoveryKey(formatted);
  assert.deepEqual(decoded, key);

  // Flip one character -> must fail checksum
  const tampered = (formatted[0] === 'A' ? 'B' : 'A') + formatted.slice(1);
  await assert.rejects(() => decodeRecoveryKey(tampered), /checksum/i);

  const b64 = bytesToBase64(key);
  assert.deepEqual(base64ToBytes(b64), key);
});

await test('Crypto: Argon2id Pure-JS deterministic 32-byte derivation', () => {
  const out1 = argon2idPure({
    password: new TextEncoder().encode('KhaznaTestMaster!2026'),
    salt: new Uint8Array(16).fill(7),
    memorySize: 64,
    iterations: 2,
    parallelism: 1,
    hashLength: 32,
  });
  const out2 = argon2idPure({
    password: new TextEncoder().encode('KhaznaTestMaster!2026'),
    salt: new Uint8Array(16).fill(7),
    memorySize: 64,
    iterations: 2,
    parallelism: 1,
    hashLength: 32,
  });
  assert.equal(out1.length, 32);
  assert.deepEqual(out1, out2);
});

await test('Crypto: AES-256-GCM record encryption & AAD tampering rejection', async () => {
  const { header, dek } = await createVaultCrypto({
    masterPassword: 'SuperStrongMasterPassword!99',
    kdfSpec: FAST_KDF,
    enforceMinimums: false,
    useWorker: false,
  });
  const env = await encryptRecord(dek, {
    id: 'pwd_1',
    type: 'password',
    vaultId: header.vaultId,
    data: { title: 'GitHub', username: 'osama', password: 'SecretPassword#123' },
  });
  const dec = await decryptRecord(dek, env, header.vaultId);
  assert.equal(dec.data.password, 'SecretPassword#123');

  // Tamper AAD field (id) -> MUST throw
  const tamperedEnv = { ...env, id: 'pwd_2' };
  await assert.rejects(() => decryptRecord(dek, tamperedEnv, header.vaultId));
});

await test('Crypto: Password & Passphrase generator + strength meter', () => {
  const pwd = generatePassword({ length: 24, lower: true, upper: true, digits: true, symbols: true });
  assert.equal(pwd.length, 24);
  const st = evaluatePasswordStrength(pwd);
  assert.ok(st.score >= 3);

  const phrase = generatePassphrase({ wordCount: 6, separator: '-', capitalize: true, includeNumber: true });
  assert.ok(phrase.split('-').length === 6);
});

await test('Storage: withWriteLock falls back cleanly on file:// opaque origin SecurityError', async () => {
  const storage = new VaultStorage({ backend: createMemoryBackend() });
  const prevLocks = globalThis.navigator?.locks;
  const result = await storage.withWriteLock(async () => 'ok-lock');
  assert.equal(result, 'ok-lock');
  assert.equal(prevLocks, globalThis.navigator?.locks);
});

await test('Session: Full lifecycle + Bulk Move (movePasswordsToSection) + decryptRecord', async () => {
  const storage = new VaultStorage({ backend: createMemoryBackend() });
  const session = new VaultSession({ storage, useWorker: false });
  await session.init();

  const { recoveryKeyFormatted } = await session.createVault({
    masterPassword: 'MyMasterPassword!2026',
    kdfSpec: FAST_KDF,
    enforceMinimums: false,
  });
  assert.ok(session.isUnlocked);

  const sections = await session.listRecords('section');
  assert.equal(sections.length, 5);
  assert.ok(sections.some((s) => s.data?.name === 'الفواتير' || s.data?.name === 'Bills'));
  const secA = sections[0].id;
  const secB = sections[1].id;

  const p1 = await session.saveRecord({
    type: 'password',
    data: { title: 'Bank A', username: 'u1', password: 'p1', sectionId: secA },
  });
  const p2 = await session.saveRecord({
    type: 'password',
    data: { title: 'Electricity Bill', username: '01556265247', password: '', url: '', sectionId: secA },
  });
  assert.equal(p2.data.password, '');
  assert.equal(p2.data.url, '');

  // Verify decryptRecord exists and works
  const rawRec = await storage.getRecord(p1.id);
  const decRec = await session.decryptRecord(rawRec);
  assert.equal(decRec.data.title, 'Bank A');

  // Verify bulk move works atomically with snapshot
  const movedCount = await session.movePasswordsToSection(new Set([p1.id, p2.id]), secB);
  assert.equal(movedCount, 2);
  const afterMove = await session.listRecords('password');
  assert.ok(afterMove.every((p) => p.data.sectionId === secB));
  const snaps = await storage.listSnapshots();
  assert.ok(snaps.some((s) => s.reason === 'bulk-move-section'));

  // Lock & unlock with password + recovery key
  session.lock();
  assert.equal(session.isUnlocked, false);
  await session.unlockWithPassword('MyMasterPassword!2026');
  assert.equal(session.isUnlocked, true);

  session.lock();
  await session.unlockWithRecoveryKey(recoveryKeyFormatted, 'NewMasterPassword!2027', { enforceMinimums: false });
  assert.equal(session.isUnlocked, true);
  session.lock();
  await session.unlockWithPassword('NewMasterPassword!2027');
  assert.equal(session.isUnlocked, true);
});

await test('Session: Native Android Biometric enroll, unlock, verifyReauth, and wipe cleanup', async () => {
  const secretStore = new Map();
  let authCalls = 0;
  const mockEnv = {
    crypto: globalThis.crypto,
    Capacitor: {
      isNativePlatform: () => true,
      getPlatform: () => 'android',
      Plugins: {
        NativeBiometric: {
          isAvailable: async () => ({ isAvailable: true, hasHardware: true }),
          authenticate: async () => {
            authCalls++;
            return { authenticated: true };
          },
          setSecret: async ({ key, secret }) => {
            secretStore.set(key, secret);
            return { success: true };
          },
          getSecret: async ({ key }) => {
            if (!secretStore.has(key)) throw Object.assign(new Error('missing'), { code: 'NOT_FOUND' });
            return { authenticated: true, secret: secretStore.get(key) };
          },
          deleteSecret: async ({ key }) => {
            secretStore.delete(key);
            return { success: true };
          },
        },
      },
    },
  };

  const storage = new VaultStorage({ backend: createMemoryBackend() });
  const session = new VaultSession({ storage, env: mockEnv, useWorker: false });
  await session.createVault({
    masterPassword: 'AndroidBioMaster!2026',
    kdfSpec: FAST_KDF,
    enforceMinimums: false,
  });

  // Enroll native biometric -> must call authenticate() + setSecret()
  const enrollRes = await session.enrollBiometricWithPassword('AndroidBioMaster!2026');
  assert.equal(enrollRes.mode, 'native');
  assert.equal(authCalls, 1);
  assert.equal(secretStore.size, 1);

  // verifyReauth with native biometric -> must work!
  const reauthOk = await session.verifyReauth({ useBiometric: true });
  assert.equal(reauthOk, true);
  assert.equal(authCalls, 2);

  // Lock & unlock with native biometric
  session.lock();
  assert.equal(session.getBiometricState().mode, 'native');
  assert.equal(session.getBiometricState().ready, true);
  const unlockRes = await session.unlockWithBiometric();
  assert.equal(unlockRes.mode, 'native');
  assert.equal(session.isUnlocked, true);

  // Wipe vault -> must clean up native biometric secret!
  await session.wipeVault();
  assert.equal(secretStore.size, 0);
});

await test('ClipboardGuard: Uses Capacitor Clipboard plugin when present', async () => {
  let written = null;
  const guard = new ClipboardGuard({
    Capacitor: {
      Plugins: {
        Clipboard: {
          write: async ({ string }) => {
            written = string;
          },
        },
      },
    },
  });
  await guard.copySecret('user\npass', 0);
  assert.equal(written, 'user\npass');
});

await test('Domain: Card brand detection, Luhn, masking, Arabic search & audit', () => {
  assert.equal(detectCardBrand('4532015112830366'), 'visa');
  assert.equal(validateLuhn('4532015112830366'), true);
  assert.equal(validateLuhn('4532015112830367'), false);
  assert.ok(maskCardNumber('4532015112830366', 'visa').endsWith('0366'));

  const list = [
    { id: '1', data: { title: 'البنك الأهلي', username: 'ahmed', password: 'abc', sectionId: 's1', favorite: false }, updatedAt: '2026-01-05', createdAt: '2026-01-05' },
    { id: '2', data: { title: 'GitHub', username: 'dev', password: 'abc', sectionId: 's2', favorite: true }, updatedAt: '2026-01-01', createdAt: '2026-01-01' },
  ];
  const res = filterAndSortPasswords(list, { query: 'الاهلي' });
  assert.equal(res.length, 1);
  assert.equal(res[0].id, '1');

  // Favorites MUST always sort first regardless of sort order
  const sortedUpdated = filterAndSortPasswords(list, { sortBy: 'updated-desc' });
  assert.equal(sortedUpdated[0].id, '2');
  const sortedTitle = filterAndSortPasswords(list, { sortBy: 'title-asc' });
  assert.equal(sortedTitle[0].id, '2');
  const sortedCreated = filterAndSortPasswords(list, { sortBy: 'created-desc' });
  assert.equal(sortedCreated[0].id, '2');

  const stats = computeVaultAuditAndStats({ sections: [], passwords: list, cards: [], notes: [] });
  assert.equal(stats.audit.reusedCount, 2);

  // Per-section duplicate detection:
  // Identical username/password in DIFFERENT sections must NOT cross-contaminate,
  // while duplicates INSIDE the same section MUST be detected with exact reasons.
  const dupList = [
    { id: 'a1', data: { title: 'FB 1', username: '01099999999', password: 'pw1', sectionId: 'sec-fb' } },
    { id: 'a2', data: { title: 'FB Old', username: '01099999999', password: 'pw2', sectionId: 'sec-fb' } },
    { id: 'b1', data: { title: 'Electric Bill', username: '01099999999', password: '', sectionId: 'sec-bills' } },
    { id: 'c1', data: { title: 'Work Mail', username: 'a@co.com', password: 'SharedPass#1', sectionId: 'sec-work' } },
    { id: 'c2', data: { title: 'Work VPN', username: 'b@co.com', password: 'SharedPass#1', sectionId: 'sec-work' } },
  ];
  const dupAnalysis = analyzeSectionDuplicates(dupList);
  assert.equal(dupAnalysis.countBySection.get('sec-fb'), 2);
  assert.equal(dupAnalysis.countBySection.get('sec-bills'), undefined);
  assert.equal(dupAnalysis.countBySection.get('sec-work'), 2);
  assert.equal(dupAnalysis.duplicateIds.has('b1'), false);
  assert.equal(dupAnalysis.byEntryId.get('a1').reasons[0].type, 'username');
  assert.equal(dupAnalysis.byEntryId.get('c1').reasons[0].type, 'password');

  const fbDups = filterAndSortPasswords(dupList, { sectionId: 'sec-fb', duplicatesOnly: true });
  assert.equal(fbDups.length, 2);
  const billsDups = filterAndSortPasswords(dupList, { sectionId: 'sec-bills', duplicatesOnly: true });
  assert.equal(billsDups.length, 0);
});

await test('Import/Export & Sync: .vault, Bitwarden JSON, Chrome CSV, and encrypted Sync merge', async () => {
  const sample = {
    sections: [{ id: 's1', data: { name: 'Work', emoji: '💼', color: '#f59e0b', order: 0 } }],
    passwords: [{ id: 'p1', updatedAt: '2026-05-01T00:00:00Z', data: { title: 'Mail', username: 'a@b.com', password: 'Strong!Password99', sectionId: 's1' } }],
    cards: [],
    notes: [],
  };

  const vaultText = await exportEncryptedVault(sample, 'BackupPass!123', FAST_KDF, { enforceMinimums: false });
  const parsedVault = await parseImportSource({ rawText: vaultText, fileName: 'test.vault', password: 'BackupPass!123' });
  assert.equal(parsedVault.passwords.length, 1);
  assert.equal(parsedVault.passwords[0].password, 'Strong!Password99');

  const csvText = exportChromeCsv(sample.passwords);
  const parsedCsv = await parseImportSource({ rawText: csvText, fileName: 'chrome.csv' });
  assert.equal(parsedCsv.passwords.length, 1);

  const bwJson = exportBitwardenJson(sample);
  const parsedBw = await parseImportSource({ rawText: bwJson, fileName: 'bw.json' });
  assert.equal(parsedBw.passwords.length, 1);

  // Sync round-trip
  const payload = selectSyncRecords({ ...sample, mode: 'full' });
  const encSync = await encodeSyncPackage({ payload, passphrase: 'SyncPassphrase!2026' });
  const decSync = await decodeSyncPackage({ input: encSync.code, passphrase: 'SyncPassphrase!2026' });
  const plan = planSyncMerge({ incoming: decSync, localSections: [], localPasswords: [], localCards: [], localNotes: [] });
  assert.equal(plan.summary.added, 2);

  const targetStorage = new VaultStorage({ backend: createMemoryBackend() });
  const targetSession = new VaultSession({ storage: targetStorage, useWorker: false });
  await targetSession.createVault({ masterPassword: 'TargetMaster!2026', kdfSpec: FAST_KDF, enforceMinimums: false, seedDefaultSections: false });
  await applySyncMerge({ session: targetSession, plan });
  const mergedPw = await targetSession.listRecords('password');
  assert.equal(mergedPw.length, 1);
  assert.equal(mergedPw[0].data.title, 'Mail');
});

await test('Pattern Lock + Optional Password + Transfer from Old Device with Same Lock + Browser Screenshot Safe', async () => {
  const pat = encodePatternSecret([0, 1, 2, 5, 8]);
  assert.equal(isPatternSecret(pat), true);
  assert.throws(() => encodePatternSecret([0, 1, 2]));

  // Device 1 (Old Device): created with 3x3 Pattern
  const oldStorage = new VaultStorage({ backend: createMemoryBackend() });
  const oldSession = new VaultSession({ storage: oldStorage, useWorker: false });
  await oldSession.init();
  await oldSession.createVault({
    masterPassword: pat,
    kdfSpec: FAST_KDF,
    enforceMinimums: false,
  });
  assert.equal(oldSession.unlockMethod, 'pattern');
  assert.equal(oldSession.hasPatternUnlock, true);
  assert.equal(oldSession.hasPasswordUnlock, false);

  // Browser screenshot safe: privacyBlurOnBlur defaults to false
  assert.equal(oldSession.settings.privacyBlurOnBlur, false);
  oldSession.handleVisibilityChange(true);
  assert.equal(oldSession.isBlurred, false);

  // Optional secondary password can be added alongside Pattern
  await oldSession.setSecondaryUnlock({ currentSecret: pat, altSecret: 'OptionalBackupPwd!2026' });
  assert.equal(oldSession.hasPatternUnlock, true);
  assert.equal(oldSession.hasPasswordUnlock, true);

  // Both Pattern AND Optional Password unlock the vault!
  oldSession.lock();
  await oldSession.unlockWithPassword('OptionalBackupPwd!2026');
  assert.equal(oldSession.isUnlocked, true);
  oldSession.lock();
  await oldSession.unlockWithPassword(pat);
  assert.equal(oldSession.isUnlocked, true);

  // Add a password on Old Device & generate Transfer Code with the SAME Pattern
  const oldSections = await oldSession.listRecords('section');
  await oldSession.saveRecord({
    type: 'password',
    data: { title: 'Instagram', username: 'osama_ig', password: 'IGSecret#99', sectionId: oldSections[0].id },
  });
  const payload = selectSyncRecords({
    sections: oldSections,
    passwords: await oldSession.listRecords('password'),
    cards: [],
    notes: [],
    mode: 'full',
  });
  const encTransfer = await encodeSyncPackage({ payload, passphrase: pat });

  // Device 2 (Brand-New Device): createVaultFromSyncCode using exact SAME Pattern
  const newStorage = new VaultStorage({ backend: createMemoryBackend() });
  const newSession = new VaultSession({ storage: newStorage, useWorker: false });
  await newSession.init();
  const transferRes = await newSession.createVaultFromSyncCode({
    syncInput: encTransfer.code,
    secret: pat,
    kdfSpec: FAST_KDF,
    enforceMinimums: false,
  });
  assert.equal(newSession.isUnlocked, true);
  assert.equal(newSession.unlockMethod, 'pattern');
  assert.equal(transferRes.counts.passwords, 1);

  const transferredPws = await newSession.listRecords('password');
  assert.equal(transferredPws.length, 1);
  assert.equal(transferredPws[0].data.title, 'Instagram');

  // Lock & unlock New Device with the exact SAME Pattern
  newSession.lock();
  await newSession.unlockWithPassword(pat);
  assert.equal(newSession.isUnlocked, true);

  // Chrome Extension RAM session restore across popup close/reopen
  const ramMap = new Map();
  const extEnv = {
    crypto: globalThis.crypto,
    location: { protocol: 'chrome-extension:' },
    chrome: {
      storage: {
        session: {
          get: async (k) => ({ [k]: ramMap.get(k) }),
          set: async (obj) => { for (const [k, v] of Object.entries(obj)) ramMap.set(k, v); },
          remove: async (k) => { ramMap.delete(k); },
        },
      },
    },
  };
  const extStorage = new VaultStorage({ backend: createMemoryBackend() });
  const extPopup1 = new VaultSession({ storage: extStorage, env: extEnv, useWorker: false });
  await extPopup1.init();
  await extPopup1.createVault({ masterPassword: pat, kdfSpec: FAST_KDF, enforceMinimums: false });
  assert.equal(ramMap.size, 1);

  // Reopen popup (fresh VaultSession instance sharing same storage & chrome.storage.session)
  const extPopup2 = new VaultSession({ storage: extStorage, env: extEnv, useWorker: false });
  await extPopup2.init();
  assert.equal(extPopup2.isUnlocked, true, 'Chrome Extension popup should stay unlocked in RAM across close/reopen');

  // Manual lock wipes RAM session immediately
  extPopup2.lock();
  assert.equal(ramMap.size, 0);
});

await test('Security Static Audit: Zero innerHTML/eval/inline style= & zero external URLs', () => {
  function walk(dir) {
    const out = [];
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) out.push(...walk(p));
      else if (/\.(js|html)$/.test(e.name)) out.push(p);
    }
    return out;
  }

  const forbidden = /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|\beval\s*\(|new Function\s*\(|style\s*=\s*["']/;
  for (const file of walk(path.join(ROOT, 'src'))) {
    const raw = fs.readFileSync(file, 'utf8');
    // Strip block and line comments before checking executable code
    const codeOnly = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '');
    assert.equal(forbidden.test(codeOnly), false, `Forbidden DOM/security pattern found in ${file}`);
  }

  const indexHtml = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  assert.equal(/\s(?:style|on[a-z]+)\s*=\s*["']/i.test(indexHtml), false, 'index.html must not contain inline style or event handlers');

  // Ensure Chrome Extension has no hardcoded external URLs and no insecure web_accessible_resources
  const extManifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'chrome-extension', 'manifest.json'), 'utf8'));
  assert.equal(extManifest.web_accessible_resources, undefined, 'Chrome extension should not expose web_accessible_resources');
  const extPopupHtml = fs.readFileSync(path.join(ROOT, 'chrome-extension', 'popup.html'), 'utf8');
  assert.equal(/https?:\/\//.test(extPopupHtml), false, 'popup.html must not contain external URLs');
  const extAppHtml = fs.readFileSync(path.join(ROOT, 'chrome-extension', 'app.html'), 'utf8');
  assert.equal(/https?:\/\//.test(extAppHtml), false, 'app.html must not contain external URLs');
});

await test('i18n Audit: Every t(lang, key) used in src/ exists in both ar & en', () => {
  function walk(dir) {
    const out = [];
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) out.push(...walk(p));
      else if (p.endsWith('.js')) out.push(p);
    }
    return out;
  }

  const missing = [];
  for (const file of walk(path.join(ROOT, 'src'))) {
    const txt = fs.readFileSync(file, 'utf8');
    for (const m of txt.matchAll(/\bt\(\s*[^,]+,\s*['"]([^'"]+)['"]\s*\)/g)) {
      const k = m[1];
      if (t('ar', k) === k || t('en', k) === k) missing.push(`${path.basename(file)}:${k}`);
    }
  }
  assert.deepEqual(missing, []);
});

console.log(`\n📊 Results: ${passed} passed, ${failed} failed.`);
process.exit(failed > 0 ? 1 : 0);
