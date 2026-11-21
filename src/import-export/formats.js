/**
 * Khazna Multi-Format Detection, Parsing & Export Serializers
 *
 * Supported Import Formats:
 *   - Khazna encrypted `.vault` (AES-256-GCM + Argon2id/PBKDF2)
 *   - Samsung Pass `.spass` (AES-256-CBC + PBKDF2 70,000)
 *   - Khazna plain JSON
 *   - Bitwarden JSON (logins, cards, notes, folders)
 *   - Generic JSON (flexible key synonyms)
 *   - CSV (Chrome/Edge/Brave, Firefox, Bitwarden, LastPass, 1Password, Dashlane, Apple, KeePass, Universal)
 *
 * Supported Export Formats:
 *   - `.vault` encrypted backup (recommended, full-fidelity)
 *   - Khazna plain JSON
 *   - Chrome-compatible CSV
 *   - Bitwarden-compatible JSON
 *   - Best-effort Samsung Pass `.spass`
 */

import {
  BACKUP_FORMAT_ID,
  decryptVaultBackup,
  encryptVaultBackup,
} from '../crypto/vault-crypto.js';
import { KhaznaError, randomId } from '../crypto/utils.js';
import {
  detectCsvPresetAndMapping,
  mapCsvRowsToEntries,
  parseCsv,
  serializeCsv,
} from './csv.js';
import { exportSpass, importSpass } from './spass.js';

export function detectImportFormat(rawText, fileName = '') {
  const nameLower = String(fileName || '').toLowerCase();
  const trimmed = String(rawText || '').replace(/^\uFEFF/, '').trim();

  if (!trimmed) {
    throw new KhaznaError('EMPTY_IMPORT', 'الملف أو النص المُدخل فارغ.', 'Import content is empty.');
  }

  // Try JSON formats first
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && !Array.isArray(parsed) && parsed.format === BACKUP_FORMAT_ID) {
        return { format: 'khazna-vault', requiresPassword: true };
      }
      if (parsed && !Array.isArray(parsed) && parsed.format === 'khazna-plain-json') {
        return { format: 'khazna-json', requiresPassword: false };
      }
      if (parsed && !Array.isArray(parsed) && Array.isArray(parsed.items)) {
        return { format: 'bitwarden-json', requiresPassword: false };
      }
      return { format: 'generic-json', requiresPassword: false };
    } catch {
      // Not valid JSON; continue detection
    }
  }

  // Samsung Pass .spass detection (extension OR clean Base64 blob without CSV delimiters)
  if (
    nameLower.endsWith('.spass') ||
    (!trimmed.includes(',') && !trimmed.includes(';') && !trimmed.includes('\t') &&
      /^[A-Za-z0-9+/=\r\n]{64,}$/.test(trimmed))
  ) {
    return { format: 'spass', requiresPassword: true };
  }

  // CSV fallback
  const { headers } = parseCsv(trimmed);
  if (headers.length >= 2) {
    const { preset } = detectCsvPresetAndMapping(headers);
    return { format: preset, isCsv: true, requiresPassword: false };
  }

  throw new KhaznaError(
    'UNRECOGNIZED_FORMAT',
    'تعذّر التعرّف على صيغة الملف. الصيغ المدعومة: .vault و .spass و JSON و CSV.',
    'Unrecognized import format. Supported: .vault, .spass, JSON, CSV.'
  );
}

function pickSynonym(obj, keys) {
  if (!obj || typeof obj !== 'object') return '';
  const map = new Map(Object.entries(obj).map(([k, v]) => [k.toLowerCase().trim(), v]));
  for (const key of keys) {
    const val = map.get(key.toLowerCase());
    if (val !== undefined && val !== null && val !== '') return String(val);
  }
  return '';
}

function parseBitwardenJson(parsed) {
  const folderMap = new Map();
  const sections = [];
  for (const f of parsed.folders || []) {
    if (f?.id && f?.name) {
      folderMap.set(f.id, f.name);
      sections.push({ name: f.name, emoji: '📁', color: '#38bdf8' });
    }
  }

  const passwords = [];
  const cards = [];
  const notes = [];

  for (const item of parsed.items || []) {
    const folder = item.folderId ? (folderMap.get(item.folderId) || '') : '';
    const fav = Boolean(item.favorite);

    if (item.type === 1 || item.login) {
      const login = item.login || {};
      const firstUri = Array.isArray(login.uris) && login.uris[0]?.uri ? login.uris[0].uri : '';
      passwords.push({
        title: item.name || firstUri || 'Login',
        url: firstUri,
        username: login.username || '',
        password: login.password || '',
        notes: item.notes || '',
        folder,
        favorite: fav,
      });
    } else if (item.type === 3 || item.card) {
      const c = item.card || {};
      const mm = String(c.expMonth || '').padStart(2, '0');
      const yyRaw = String(c.expYear || '');
      const yy = yyRaw.length === 4 ? yyRaw.slice(2) : yyRaw.padStart(2, '0');
      const expiry = mm !== '00' && yy !== '00' ? `${mm}/${yy}` : '';
      cards.push({
        cardName: item.name || c.brand || 'Card',
        bankName: '',
        holderName: c.cardholderName || '',
        number: String(c.number || '').replace(/[\s\-]+/g, ''),
        expiry,
        cvv: String(c.code || ''),
        pin: '',
        notes: item.notes || '',
        theme: 'obsidian',
        brandOverride: 'auto',
      });
    } else if (item.type === 2) {
      notes.push({
        title: item.name || 'Note',
        body: item.notes || '',
        checklist: [],
        pinned: fav,
      });
    }
  }

  return { sections, passwords, cards, notes, warnings: [] };
}

function parseGenericJson(parsed) {
  let list = [];
  if (Array.isArray(parsed)) {
    list = parsed;
  } else if (parsed && typeof parsed === 'object') {
    list = parsed.passwords || parsed.logins || parsed.entries || parsed.accounts || parsed.data || [];
    if (!Array.isArray(list)) list = [parsed];
  }

  const passwords = [];
  const cards = Array.isArray(parsed?.cards) ? parsed.cards : [];
  const notes = Array.isArray(parsed?.notes) ? parsed.notes : [];
  const sections = Array.isArray(parsed?.sections) ? parsed.sections : [];

  for (const row of list) {
    if (!row || typeof row !== 'object') continue;
    const title = pickSynonym(row, ['name', 'title', 'service', 'site', 'account', 'label', 'الاسم', 'العنوان']);
    const url = pickSynonym(row, ['url', 'uri', 'website', 'link', 'origin', 'domain', 'الموقع']);
    const username = pickSynonym(row, ['username', 'login', 'email', 'user', 'userid', 'اسم المستخدم']);
    const password = pickSynonym(row, ['password', 'pass', 'pwd', 'secret', 'كلمة المرور']);
    const note = pickSynonym(row, ['note', 'notes', 'memo', 'extra', 'comment', 'description', 'ملاحظات']);
    const folder = pickSynonym(row, ['folder', 'group', 'category', 'section', 'القسم', 'المجلد']);

    if (!title && !url && !username && !password) continue;
    passwords.push({
      title: title || url || username || 'Entry',
      url,
      username,
      password,
      notes: note,
      folder,
      favorite: Boolean(row.favorite || row.fav || row.starred),
    });
  }

  return { sections, passwords, cards, notes, warnings: [] };
}

/**
 * Parses any supported import source into a normalized Khazna import bundle.
 */
export async function parseImportSource({
  rawText,
  fileName = '',
  password = '',
  customCsvMapping = null,
  useWorker = true,
}) {
  const detected = detectImportFormat(rawText, fileName);

  if (detected.format === 'khazna-vault') {
    if (!password) {
      throw new KhaznaError(
        'VAULT_PASSWORD_REQUIRED',
        'أدخل كلمة مرور ملف النسخة الاحتياطية (.vault).',
        'Enter the password for this encrypted .vault backup.'
      );
    }
    const { payload } = await decryptVaultBackup(rawText, password, { useWorker });
    return {
      format: 'khazna-vault',
      sections: Array.isArray(payload.sections) ? payload.sections : [],
      passwords: Array.isArray(payload.passwords) ? payload.passwords : [],
      cards: Array.isArray(payload.cards) ? payload.cards : [],
      notes: Array.isArray(payload.notes) ? payload.notes : [],
      warnings: [],
    };
  }

  if (detected.format === 'spass') {
    const res = await importSpass(rawText, password);
    return {
      format: 'spass',
      sections: [{ name: 'Samsung Pass', emoji: '📱', color: '#38bdf8' }],
      passwords: res.passwords,
      cards: res.cards,
      notes: res.notes,
      warnings: res.warnings,
    };
  }

  if (detected.format === 'khazna-json') {
    const parsed = JSON.parse(rawText.replace(/^\uFEFF/, ''));
    return {
      format: 'khazna-json',
      sections: Array.isArray(parsed.sections) ? parsed.sections : [],
      passwords: Array.isArray(parsed.passwords) ? parsed.passwords : [],
      cards: Array.isArray(parsed.cards) ? parsed.cards : [],
      notes: Array.isArray(parsed.notes) ? parsed.notes : [],
      warnings: [],
    };
  }

  if (detected.format === 'bitwarden-json') {
    const parsed = JSON.parse(rawText.replace(/^\uFEFF/, ''));
    return {
      format: 'bitwarden-json',
      ...parseBitwardenJson(parsed),
    };
  }

  if (detected.format === 'generic-json') {
    const parsed = JSON.parse(rawText.replace(/^\uFEFF/, ''));
    return {
      format: 'generic-json',
      ...parseGenericJson(parsed),
    };
  }

  // CSV variants
  const parsedCsv = parseCsv(rawText);
  const { preset, columnMap } = detectCsvPresetAndMapping(parsedCsv.headers);
  const activeMap = customCsvMapping || columnMap;
  const mapped = mapCsvRowsToEntries({
    headers: parsedCsv.headers,
    rows: parsedCsv.rows,
    columnMap: activeMap,
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
    warnings: mapped.errors,
  };
}

// --- EXPORTERS ---

export async function exportEncryptedVault({ sections, passwords, cards, notes }, backupPassword, kdfSpec, opts = {}) {
  const payload = {
    format: 'khazna-plain-json',
    version: 1,
    exportedAt: new Date().toISOString(),
    sections: sections.map((s) => ({ id: s.id, ...s.data })),
    passwords: passwords.map((p) => ({
      id: p.id,
      ...p.data,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
    })),
    cards: cards.map((c) => ({ id: c.id, ...c.data })),
    notes: notes.map((n) => ({ id: n.id, ...n.data })),
  };
  return encryptVaultBackup(payload, backupPassword, kdfSpec, opts);
}

export function exportPlainJson({ sections, passwords, cards, notes }) {
  const sectionById = new Map(sections.map((s) => [s.id, s.data?.name || '']));
  return JSON.stringify(
    {
      format: 'khazna-plain-json',
      version: 1,
      exportedAt: new Date().toISOString(),
      sections: sections.map((s) => ({
        id: s.id,
        name: s.data?.name || '',
        emoji: s.data?.emoji || '🔐',
        color: s.data?.color || '#38bdf8',
        order: s.data?.order ?? 0,
      })),
      passwords: passwords.map((p) => ({
        title: p.data?.title || '',
        url: p.data?.url || '',
        username: p.data?.username || '',
        password: p.data?.password || '',
        notes: p.data?.notes || '',
        folder: sectionById.get(p.data?.sectionId) || '',
        favorite: Boolean(p.data?.favorite),
        passwordHistory: p.data?.passwordHistory || [],
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
      })),
      cards: cards.map((c) => ({ ...c.data })),
      notes: notes.map((n) => ({ ...n.data })),
    },
    null,
    2
  );
}

export function exportChromeCsv(passwords) {
  const headers = ['name', 'url', 'username', 'password', 'note'];
  const rows = passwords.map((p) => [
    p.data?.title || '',
    p.data?.url || '',
    p.data?.username || '',
    p.data?.password || '',
    p.data?.notes || '',
  ]);
  return serializeCsv(headers, rows, ',');
}

export function exportBitwardenJson({ sections, passwords, cards, notes }) {
  const folders = sections.map((s) => ({ id: s.id, name: s.data?.name || 'Folder' }));
  const items = [];

  for (const p of passwords) {
    items.push({
      id: p.id || randomId('bw'),
      folderId: p.data?.sectionId || null,
      type: 1,
      name: p.data?.title || '',
      notes: p.data?.notes || null,
      favorite: Boolean(p.data?.favorite),
      login: {
        uris: p.data?.url ? [{ match: null, uri: p.data.url }] : [],
        username: p.data?.username || '',
        password: p.data?.password || '',
        totp: null,
      },
    });
  }

  for (const c of cards) {
    const [mm = '', yy = ''] = String(c.data?.expiry || '').split('/');
    items.push({
      id: c.id || randomId('bw'),
      folderId: null,
      type: 3,
      name: c.data?.cardName || 'Card',
      notes: c.data?.notes || null,
      favorite: false,
      card: {
        cardholderName: c.data?.holderName || '',
        brand: c.data?.brandOverride || 'Other',
        number: c.data?.number || '',
        expMonth: mm,
        expYear: yy ? (yy.length === 2 ? `20${yy}` : yy) : '',
        code: c.data?.cvv || '',
      },
    });
  }

  for (const n of notes) {
    items.push({
      id: n.id || randomId('bw'),
      folderId: null,
      type: 2,
      name: n.data?.title || 'Note',
      notes: n.data?.body || '',
      favorite: Boolean(n.data?.pinned),
      secureNote: { type: 0 },
    });
  }

  return JSON.stringify({ encrypted: false, folders, items }, null, 2);
}

export async function exportBestEffortSpass({ passwords, cards, notes }, exportPassword) {
  return exportSpass(
    {
      passwords: passwords.map((p) => p.data || p),
      cards: cards.map((c) => c.data || c),
      notes: notes.map((n) => n.data || n),
    },
    exportPassword
  );
}
