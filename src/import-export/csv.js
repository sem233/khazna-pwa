/**
 * Khazna Universal CSV Parser & Serializer (RFC 4180 + Real-World Edge Cases)
 *
 * Handles:
 * - UTF-8 BOM stripping
 * - Quoted fields containing commas, semicolons, tabs, CRLF/LF newlines, and escaped "" quotes
 * - Automatic delimiter detection (',' vs ';' vs '\t')
 * - Arabic/UTF-8 text and large files
 * - Auto-detection presets for: Chrome/Edge/Brave, Firefox, Bitwarden, LastPass,
 *   1Password, Dashlane, Apple Passwords, KeePass, plus manual universal column mapping
 */

export const CSV_TARGET_FIELDS = Object.freeze([
  'ignore',
  'title',
  'url',
  'username',
  'password',
  'notes',
  'folder',
  'favorite',
]);

/**
 * Strips leading UTF-8 BOM and detects the best delimiter from the first logical line.
 */
export function detectCsvDelimiter(rawText) {
  const text = String(rawText || '').replace(/^\uFEFF/, '');
  const firstLineEnd = text.search(/\r?\n/);
  const sample = firstLineEnd === -1 ? text.slice(0, 2000) : text.slice(0, firstLineEnd);

  const candidates = [',', ';', '\t'];
  let bestDelim = ',';
  let bestScore = -1;

  for (const delim of candidates) {
    let inQuotes = false;
    let count = 0;
    for (let i = 0; i < sample.length; i++) {
      const ch = sample[i];
      if (ch === '"') {
        if (inQuotes && sample[i + 1] === '"') {
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (!inQuotes && ch === delim) {
        count++;
      }
    }
    if (count > bestScore) {
      bestScore = count;
      bestDelim = delim;
    }
  }
  return bestScore > 0 ? bestDelim : ',';
}

/**
 * Parses CSV text into `{ headers, rows, delimiter }`.
 */
export function parseCsv(rawText, explicitDelimiter = null) {
  const text = String(rawText || '').replace(/^\uFEFF/, '');
  if (!text.trim()) {
    return { headers: [], rows: [], delimiter: explicitDelimiter || ',' };
  }

  const delimiter = explicitDelimiter || detectCsvDelimiter(text);
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"' && field.length === 0) {
      inQuotes = true;
    } else if (ch === delimiter) {
      row.push(field);
      field = '';
    } else if (ch === '\r') {
      if (text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  // Filter trailing blank lines
  const nonEmpty = rows.filter((r) => r.some((cell) => cell.trim() !== ''));
  if (nonEmpty.length === 0) {
    return { headers: [], rows: [], delimiter };
  }

  const headers = nonEmpty[0].map((h) => h.trim());
  const dataRows = nonEmpty.slice(1);
  return { headers, rows: dataRows, delimiter };
}

/**
 * Serializes rows to RFC 4180 CSV with proper quoting.
 */
export function serializeCsv(headers, rows, delimiter = ',') {
  const escapeCell = (val) => {
    const s = String(val ?? '');
    if (s.includes('"') || s.includes(delimiter) || s.includes('\n') || s.includes('\r')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  const lines = [headers.map(escapeCell).join(delimiter)];
  for (const r of rows) {
    lines.push(r.map(escapeCell).join(delimiter));
  }
  return lines.join('\n');
}

const SYNONYMS = Object.freeze({
  title: ['name', 'title', 'account', 'service', 'site', 'website name', 'label', 'اسم', 'العنوان', 'الاسم'],
  url: ['url', 'uri', 'login_uri', 'website', 'web site', 'homepage', 'origin', 'domain', 'الموقع', 'الرابط'],
  username: ['username', 'login_username', 'user', 'login', 'email', 'e-mail', 'user name', 'userid', 'اسم المستخدم', 'البريد'],
  password: ['password', 'login_password', 'pass', 'pwd', 'secret', 'كلمة المرور', 'الرمز'],
  notes: ['note', 'notes', 'extra', 'comment', 'comments', 'memo', 'description', 'ملاحظات', 'ملاحظة'],
  folder: ['folder', 'grouping', 'group', 'category', 'collection', 'section', 'القسم', 'المجلد'],
  favorite: ['fav', 'favorite', 'favourite', 'starred', 'مفضلة'],
});

/**
 * Detects password manager CSV preset and builds an automatic column index mapping.
 */
export function detectCsvPresetAndMapping(headers) {
  const lower = headers.map((h) => h.toLowerCase().trim());
  const has = (...cols) => cols.every((c) => lower.includes(c));

  let preset = 'generic-csv';
  if (has('login_username', 'login_password')) preset = 'bitwarden-csv';
  else if (has('grouping', 'extra', 'fav')) preset = 'lastpass-csv';
  else if (has('httprealm', 'formactionorigin')) preset = 'firefox-csv';
  else if (has('otpauth', 'title', 'url', 'username', 'password')) preset = 'apple-csv';
  else if (has('group', 'title', 'username', 'password', 'url')) preset = 'keepass-csv';
  else if (has('username2', 'username3') || (has('title', 'url', 'username', 'password', 'note') && lower.includes('category'))) {
    preset = 'dashlane-csv';
  } else if (has('title', 'website', 'username', 'password')) preset = '1password-csv';
  else if (has('name', 'url', 'username', 'password')) preset = 'chrome-csv';

  /** @type {Record<number, string>} */
  const columnMap = {};
  const assigned = new Set();

  for (let i = 0; i < lower.length; i++) {
    const h = lower[i];
    let matched = 'ignore';
    for (const [target, keys] of Object.entries(SYNONYMS)) {
      if (!assigned.has(target) && keys.includes(h)) {
        matched = target;
        assigned.add(target);
        break;
      }
    }
    columnMap[i] = matched;
  }

  return { preset, columnMap };
}

/**
 * Converts parsed CSV rows into Khazna password entries using a column mapping.
 */
export function mapCsvRowsToEntries({ headers, rows, columnMap }) {
  const passwords = [];
  const errors = [];

  for (let rIdx = 0; rIdx < rows.length; rIdx++) {
    const row = rows[rIdx];
    const item = {
      title: '',
      url: '',
      username: '',
      password: '',
      notes: '',
      folder: '',
      favorite: false,
    };

    for (let cIdx = 0; cIdx < headers.length; cIdx++) {
      const target = columnMap[cIdx];
      if (!target || target === 'ignore') continue;
      const val = row[cIdx] ?? '';
      if (target === 'favorite') {
        item.favorite = /^(1|true|yes|y)$/i.test(val.trim());
      } else if (target === 'notes') {
        item.notes = item.notes ? `${item.notes}\n${val}` : val;
      } else if (!item[target]) {
        item[target] = val.trim();
      }
    }

    // Fallback title from URL hostname if blank
    if (!item.title && item.url) {
      try {
        const u = new URL(/^[a-z]+:\/\//i.test(item.url) ? item.url : `https://${item.url}`);
        item.title = u.hostname.replace(/^www\./i, '');
      } catch {
        item.title = item.url;
      }
    }

    if (!item.title && !item.username && !item.password && !item.url) {
      continue;
    }
    if (!item.title) {
      item.title = item.username || `Row ${rIdx + 2}`;
    }

    passwords.push(item);
  }

  return { passwords, errors };
}
