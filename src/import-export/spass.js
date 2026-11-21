/**
 * Samsung Pass (.spass) Tolerant Local Parser & Best-Effort Exporter
 *
 * Format specification (unofficial/proprietary):
 *   Base64 text -> raw bytes = [20-byte salt][16-byte IV][AES-256-CBC (PKCS7) ciphertext]
 *   Key = PBKDF2-HMAC-SHA-256(exportPassword, salt, 70_000 iterations, 32 bytes)
 *
 * Decrypted plaintext is versioned, semicolon-delimited text separated by "next_table" markers,
 * with distinct tables for passwords (logins), cards (often partial: first 6 + last 4 digits),
 * addresses, and notes. Certain columns (or entire fields) are Base64-encoded UTF-8 strings;
 * this parser detects and safely decodes them while failing cleanly with explicit errors on
 * wrong password or malformed files (never failing silently).
 */

import { derivePbkdf2Sha256 } from '../crypto/kdf.js';
import {
  base64ToBytes,
  bytesToBase64,
  concatBytes,
  KhaznaError,
  randomBytes,
  utf8Decode,
  utf8Encode,
  zeroize,
} from '../crypto/utils.js';

export const SPASS_PBKDF2_ITERATIONS = 70000;
export const SPASS_SALT_LEN = 20;
export const SPASS_IV_LEN = 16;

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Safely decodes a possibly Base64-encoded Samsung Pass field.
 * Samsung Pass encodes many columns (including username, password, title, memo, card fields)
 * as Base64; literal sentinel values like "&&&NULL&&&" or plain URLs/numbers are handled cleanly.
 */
function decodeSpassField(raw, forceBase64 = false) {
  const s = String(raw ?? '').trim();
  if (!s || s === '&&&NULL&&&' || s === 'null' || s === 'NULL') return '';

  if (forceBase64 || (s.length >= 4 && s.length % 4 === 0 && BASE64_PATTERN.test(s))) {
    // Avoid mis-decoding plain lowercase/uppercase identifiers like "Visa" or "true" unless forced
    if (!forceBase64 && (/^[a-zA-Z]{4,8}$/.test(s) || /^\d{4,16}$/.test(s))) {
      return s;
    }
    try {
      const bytes = base64ToBytes(s);
      const decoded = utf8Decode(bytes);
      // Reject decoded output containing unexpected control bytes (non-printable binary)
      if (!/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(decoded)) {
        if (decoded === '&&&NULL&&&') return '';
        return decoded;
      }
    } catch {
      // Not valid UTF-8 Base64; keep original string
    }
  }
  return s;
}

function encodeSpassField(val) {
  const s = String(val ?? '');
  if (!s) return '&&&NULL&&&';
  return bytesToBase64(utf8Encode(s));
}

/**
 * Decrypts a Samsung Pass `.spass` file text into UTF-8 plaintext using WebCrypto AES-256-CBC.
 */
export async function decryptSpass(rawBase64Text, password) {
  if (!password) {
    throw new KhaznaError(
      'SPASS_PASSWORD_REQUIRED',
      'أدخل كلمة المرور التي اخترتها عند تصدير ملف Samsung Pass (.spass).',
      'Enter the export password used when creating the Samsung Pass (.spass) file.'
    );
  }

  let rawBytes;
  try {
    rawBytes = base64ToBytes(rawBase64Text);
  } catch (err) {
    throw new KhaznaError(
      'SPASS_INVALID_FORMAT',
      'ملف .spass غير صالح (فشل فك ترميز Base64 الخارجي).',
      'Invalid .spass file (outer Base64 decoding failed).',
      err
    );
  }

  if (rawBytes.length < SPASS_SALT_LEN + SPASS_IV_LEN + 16) {
    throw new KhaznaError(
      'SPASS_TOO_SHORT',
      'ملف .spass ناقص أو تالف (حجمه أصغر من الحد الأدنى المطلوب).',
      '.spass file is truncated or corrupted.'
    );
  }

  const salt = rawBytes.subarray(0, SPASS_SALT_LEN);
  const iv = rawBytes.subarray(SPASS_SALT_LEN, SPASS_SALT_LEN + SPASS_IV_LEN);
  const ciphertext = rawBytes.subarray(SPASS_SALT_LEN + SPASS_IV_LEN);

  if (ciphertext.length % 16 !== 0) {
    throw new KhaznaError(
      'SPASS_BAD_BLOCK_LEN',
      'ملف .spass تالف (طول النص المشفّر غير متوافق مع AES-CBC).',
      '.spass ciphertext length is not a multiple of AES block size.'
    );
  }

  const pwdBytes = utf8Encode(password);
  let keyBytes = null;
  let plainBytes = null;
  try {
    keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, SPASS_PBKDF2_ITERATIONS, 32);
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-CBC', length: 256 },
      false,
      ['decrypt']
    );
    const decrypted = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      ciphertext
    );
    plainBytes = new Uint8Array(decrypted);
    const text = utf8Decode(plainBytes);
    if (!text.includes(';') && !text.includes('next_table')) {
      throw new KhaznaError(
        'SPASS_UNEXPECTED_CONTENT',
        'تم فك التشفير لكن بنية ملف .spass غير متوقعة. تأكد من كلمة المرور وإصدار Samsung Pass.',
        'Decrypted .spass content has unexpected structure. Verify password and export version.'
      );
    }
    return text;
  } catch (err) {
    if (err instanceof KhaznaError) throw err;
    throw new KhaznaError(
      'SPASS_DECRYPT_FAILED',
      'فشل فك تشفير ملف .spass — كلمة مرور التصدير غير صحيحة أو الملف تالف.',
      'Failed to decrypt .spass file — wrong export password or corrupted file.',
      err
    );
  } finally {
    zeroize(pwdBytes, keyBytes, plainBytes);
  }
}

/**
 * Splits decrypted Samsung Pass plaintext into logical tables and parses logins, cards, and notes.
 */
export function parseSpassPlaintext(plaintext) {
  const lines = String(plaintext || '')
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length < 2) {
    throw new KhaznaError(
      'SPASS_EMPTY',
      'ملف Samsung Pass فارغ أو لا يحتوي على جداول بيانات.',
      'Samsung Pass plaintext contains no data tables.'
    );
  }

  // Extract version/flags header lines before first "next_table"
  let cursor = 0;
  let formatVersion = lines[0];
  const tables = [];

  while (cursor < lines.length) {
    if (lines[cursor].toLowerCase() === 'next_table') {
      cursor++;
      const tableLines = [];
      while (cursor < lines.length && lines[cursor].toLowerCase() !== 'next_table') {
        tableLines.push(lines[cursor]);
        cursor++;
      }
      if (tableLines.length > 0) tables.push(tableLines);
    } else {
      cursor++;
    }
  }

  // Fallback if a simplified export has no "next_table" marker (starts directly with header row)
  if (tables.length === 0) {
    const headerIdx = lines.findIndex((l) => l.includes(';') && /url|username|password|card|note/i.test(l));
    if (headerIdx !== -1) {
      tables.push(lines.slice(headerIdx));
    }
  }

  const passwords = [];
  const cards = [];
  const notes = [];
  const warnings = [];

  for (const table of tables) {
    const headerCols = table[0].split(';').map((c) => c.trim().toLowerCase());
    const dataLines = table.slice(1);
    if (dataLines.length === 0) continue;

    const colIdx = (...names) => {
      for (const n of names) {
        const i = headerCols.indexOf(n);
        if (i !== -1) return i;
      }
      return -1;
    };

    // Detect table type by column names
    const isPasswordTable =
      colIdx('password_value', 'password') !== -1 &&
      colIdx('origin_url', 'action_url', 'host_url', 'url', 'username_value', 'username') !== -1;

    const isCardTable =
      colIdx('card_number', 'card_number_encrypted', 'name_on_card', 'expiration_month', 'card_holder') !== -1;

    const isNoteTable =
      colIdx('note_title', 'note_detail', 'note_content', 'title', 'body') !== -1 &&
      !isPasswordTable &&
      !isCardTable;

    if (isPasswordTable) {
      const iTitle = colIdx('credential_memo', 'title', 'name', 'app_name', 'host_url');
      const iUrl = colIdx('origin_url', 'action_url', 'host_url', 'url');
      const iUser = colIdx('username_value', 'username', 'id');
      const iPass = colIdx('password_value', 'password');
      const iNote = colIdx('credential_memo', 'note', 'memo', 'extra');
      const iName = colIdx('title', 'name', 'app_name', 'package_name');

      for (const line of dataLines) {
        const cols = line.split(';');
        const url = iUrl !== -1 ? decodeSpassField(cols[iUrl]) : '';
        const username = iUser !== -1 ? decodeSpassField(cols[iUser]) : '';
        const password = iPass !== -1 ? decodeSpassField(cols[iPass]) : '';
        const rawTitle = iName !== -1 ? decodeSpassField(cols[iName]) : (iTitle !== -1 ? decodeSpassField(cols[iTitle]) : '');
        const memo = iNote !== -1 && iNote !== iName ? decodeSpassField(cols[iNote]) : '';

        if (!url && !username && !password && !rawTitle) continue;
        let title = rawTitle;
        if (!title && url) {
          try {
            title = new URL(/^[a-z]+:\/\//i.test(url) ? url : `https://${url}`).hostname.replace(/^www\./i, '');
          } catch {
            title = url;
          }
        }
        passwords.push({
          title: title || username || 'Samsung Pass',
          url,
          username,
          password,
          notes: memo,
          folder: 'Samsung Pass',
          favorite: false,
        });
      }
    } else if (isCardTable) {
      const iLabel = colIdx('card_nickname', 'card_name', 'title', 'label');
      const iBank = colIdx('bank_name', 'issuer', 'bank');
      const iHolder = colIdx('name_on_card', 'card_holder', 'holder_name');
      const iNum = colIdx('card_number', 'card_number_encrypted', 'number');
      const iFirst6 = colIdx('card_first_six', 'first_six', 'bin');
      const iLast4 = colIdx('card_last_four', 'last_four');
      const iMonth = colIdx('expiration_month', 'exp_month', 'month');
      const iYear = colIdx('expiration_year', 'exp_year', 'year');
      const iExpiry = colIdx('expiration_date', 'expiry');
      const iCvv = colIdx('cvv', 'security_code', 'card_cvv');
      const iNote = colIdx('memo', 'note', 'notes');

      for (const line of dataLines) {
        const cols = line.split(';');
        const cardName = iLabel !== -1 ? decodeSpassField(cols[iLabel]) : '';
        const bankName = iBank !== -1 ? decodeSpassField(cols[iBank]) : '';
        const holderName = iHolder !== -1 ? decodeSpassField(cols[iHolder]) : '';
        let number = iNum !== -1 ? decodeSpassField(cols[iNum]) : '';

        // Samsung Pass often exports partial cards: first 6 + last 4 digits or masked middle digits
        if (!number && (iFirst6 !== -1 || iLast4 !== -1)) {
          const f6 = iFirst6 !== -1 ? decodeSpassField(cols[iFirst6]) : '';
          const l4 = iLast4 !== -1 ? decodeSpassField(cols[iLast4]) : '';
          if (f6 || l4) {
            number = `${f6 || '******'}******${l4 || '****'}`;
          }
        }
        // Normalize partial markers like 'X' or '•' into '*'
        number = number.replace(/[\s\-]+/g, '').replace(/[xX•]/g, '*');

        let expiry = iExpiry !== -1 ? decodeSpassField(cols[iExpiry]) : '';
        if (!expiry && (iMonth !== -1 || iYear !== -1)) {
          const mm = (iMonth !== -1 ? decodeSpassField(cols[iMonth]) : '').padStart(2, '0');
          const yyRaw = iYear !== -1 ? decodeSpassField(cols[iYear]) : '';
          const yy = yyRaw.length === 4 ? yyRaw.slice(2) : yyRaw.padStart(2, '0');
          if (mm !== '00' && yy !== '00') expiry = `${mm}/${yy}`;
        }

        const cvv = iCvv !== -1 ? decodeSpassField(cols[iCvv]) : '';
        const notesText = iNote !== -1 ? decodeSpassField(cols[iNote]) : '';
        if (!cardName && !holderName && !number) continue;

        const isPartial = number.includes('*') || number.length < 13;
        cards.push({
          cardName: cardName || bankName || 'بطاقة Samsung Pass',
          bankName,
          holderName,
          number,
          expiry,
          cvv,
          pin: '',
          notes: notesText,
          theme: 'aurora',
          brandOverride: 'auto',
          partial: isPartial,
        });
      }
    } else if (isNoteTable) {
      const iTitle = colIdx('note_title', 'title', 'name');
      const iBody = colIdx('note_detail', 'note_content', 'body', 'content', 'note');

      for (const line of dataLines) {
        const cols = line.split(';');
        const title = iTitle !== -1 ? decodeSpassField(cols[iTitle]) : '';
        const body = iBody !== -1 ? decodeSpassField(cols[iBody]) : '';
        if (!title && !body) continue;
        notes.push({
          title: title || 'ملاحظة Samsung Pass',
          body,
          checklist: [],
          pinned: false,
        });
      }
    } else {
      warnings.push(`Skipped unrecognized Samsung Pass table (${headerCols.slice(0, 3).join(', ')})`);
    }
  }

  return {
    formatVersion,
    passwords,
    cards,
    notes,
    warnings,
  };
}

/**
 * Full decode + decrypt + parse pipeline for `.spass` files.
 */
export async function importSpass(rawBase64Text, password) {
  const plaintext = await decryptSpass(rawBase64Text, password);
  return parseSpassPlaintext(plaintext);
}

/**
 * Best-effort Samsung Pass `.spass` exporter (produces the exact same AES-256-CBC + PBKDF2 70k
 * versioned semicolon-delimited structure).
 */
export async function exportSpass({ passwords = [], cards = [], notes = [] }, exportPassword) {
  if (!exportPassword || exportPassword.length < 4) {
    throw new KhaznaError(
      'SPASS_EXPORT_PASSWORD_REQUIRED',
      'أدخل كلمة مرور لتشفير ملف .spass (٤ أحرف على الأقل).',
      'Enter an export password (at least 4 characters) for .spass export.'
    );
  }

  const lines = [];
  lines.push('28');
  lines.push(`${passwords.length > 0};${cards.length > 0};false;${notes.length > 0}`);

  // Table 1: Passwords
  lines.push('next_table');
  lines.push('id;origin_url;action_url;username_element;username_value;password_element;password_value;host_url;title;credential_memo');
  passwords.forEach((p, idx) => {
    lines.push([
      String(idx + 1),
      encodeSpassField(p.url || ''),
      encodeSpassField(p.url || ''),
      '&&&NULL&&&',
      encodeSpassField(p.username || ''),
      '&&&NULL&&&',
      encodeSpassField(p.password || ''),
      encodeSpassField(p.url || ''),
      encodeSpassField(p.title || ''),
      encodeSpassField(p.notes || ''),
    ].join(';'));
  });

  // Table 2: Cards
  lines.push('next_table');
  lines.push('id;card_nickname;bank_name;name_on_card;card_number;expiration_month;expiration_year;cvv;memo');
  cards.forEach((c, idx) => {
    const [mm = '', yy = ''] = String(c.expiry || '').split('/');
    lines.push([
      String(idx + 1),
      encodeSpassField(c.cardName || ''),
      encodeSpassField(c.bankName || ''),
      encodeSpassField(c.holderName || ''),
      encodeSpassField(c.number || ''),
      encodeSpassField(mm),
      encodeSpassField(yy ? (yy.length === 2 ? `20${yy}` : yy) : ''),
      encodeSpassField(c.cvv || ''),
      encodeSpassField(c.notes || ''),
    ].join(';'));
  });

  // Table 3: Notes
  lines.push('next_table');
  lines.push('id;note_title;note_detail');
  notes.forEach((n, idx) => {
    const bodyWithChecklist = n.checklist?.length
      ? `${n.body || ''}\n${n.checklist.map((i) => `${i.done ? '[x]' : '[ ]'} ${i.text}`).join('\n')}`.trim()
      : (n.body || '');
    lines.push([
      String(idx + 1),
      encodeSpassField(n.title || ''),
      encodeSpassField(bodyWithChecklist),
    ].join(';'));
  });

  const plaintextBytes = utf8Encode(lines.join('\n'));
  const salt = randomBytes(SPASS_SALT_LEN);
  const iv = randomBytes(SPASS_IV_LEN);
  const pwdBytes = utf8Encode(exportPassword);

  let keyBytes = null;
  try {
    keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, SPASS_PBKDF2_ITERATIONS, 32);
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt']
    );
    const ctBuf = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      plaintextBytes
    );
    const combined = concatBytes(salt, iv, new Uint8Array(ctBuf));
    return bytesToBase64(combined);
  } finally {
    zeroize(plaintextBytes, pwdBytes, keyBytes);
  }
}
