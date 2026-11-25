/**
 * Khazna Instant Local Search, Filtering, Sorting & Duplicate Detection
 *
 * - Arabic diacritics (Tashkeel) & letter normalization (أ/إ/آ -> ا, ة -> ه, ى -> ي, Tatweel removal)
 * - English case-insensitive matching
 * - Zero external requests
 */

const ARABIC_DIACRITICS_RE = /[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED\u0640]/g;

/**
 * Normalizes Arabic & Latin text for forgiving local search.
 */
export function normalizeSearchText(input) {
  return String(input || '')
    .normalize('NFKD')
    .replace(ARABIC_DIACRITICS_RE, '')
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ة/g, 'ه')
    .replace(/ى/g, 'ي')
    .replace(/ؤ/g, 'و')
    .replace(/ئ/g, 'ي')
    .toLowerCase()
    .trim();
}

/**
 * Checks whether `query` matches across any of the candidate fields.
 */
export function matchesQuery(query, fields) {
  const normQ = normalizeSearchText(query);
  if (!normQ) return true;
  const tokens = normQ.split(/\s+/).filter(Boolean);
  const haystack = fields.map((f) => normalizeSearchText(f)).join(' ');
  return tokens.every((tok) => haystack.includes(tok));
}

/**
 * Filters and sorts password entries locally.
 */
export function filterAndSortPasswords(
  entries,
  {
    query = '',
    sectionId = 'all',
    favoritesOnly = false,
    duplicatesOnly = false,
    sortBy = 'updated-desc',
  } = {}
) {
  let duplicateIdSet = null;
  if (duplicatesOnly) {
    duplicateIdSet = findDuplicateEntryIds(entries);
  }

  const filtered = entries.filter((entry) => {
    const d = entry.data || {};
    if (sectionId && sectionId !== 'all' && d.sectionId !== sectionId) return false;
    if (favoritesOnly && !d.favorite) return false;
    if (duplicateIdSet && !duplicateIdSet.has(entry.id)) return false;
    if (query) {
      return matchesQuery(query, [d.title, d.username, d.url, d.notes]);
    }
    return true;
  });

  filtered.sort((a, b) => {
    const da = a.data || {};
    const db = b.data || {};
    // Favorites / pinned items ALWAYS appear at the top of their section
    if (Boolean(da.favorite) !== Boolean(db.favorite)) {
      return da.favorite ? -1 : 1;
    }
    if (sortBy === 'title-asc') {
      return String(da.title || '').localeCompare(String(db.title || ''), 'ar');
    }
    if (sortBy === 'title-desc') {
      return String(db.title || '').localeCompare(String(da.title || ''), 'ar');
    }
    if (sortBy === 'created-desc') {
      return String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
    }
    // default: updated-desc
    return String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''));
  });

  return filtered;
}

/**
 * Detects duplicate password entries (same normalized URL+username or title+username, OR identical reused password).
 */
export function findDuplicateEntryIds(entries) {
  const byKey = new Map();
  const byPwd = new Map();
  const dupIds = new Set();

  for (const entry of entries) {
    const d = entry.data || {};
    const urlHost = extractHost(d.url);
    const user = normalizeSearchText(d.username);
    const title = normalizeSearchText(d.title);

    const identityKey = urlHost && user
      ? `u:${urlHost}|${user}`
      : (title && user ? `t:${title}|${user}` : null);

    if (identityKey) {
      const list = byKey.get(identityKey) || [];
      list.push(entry.id);
      byKey.set(identityKey, list);
    }

    if (d.password && d.password.length >= 4) {
      const pList = byPwd.get(d.password) || [];
      pList.push(entry.id);
      byPwd.set(d.password, pList);
    }
  }

  for (const ids of byKey.values()) {
    if (ids.length > 1) ids.forEach((id) => dupIds.add(id));
  }
  for (const ids of byPwd.values()) {
    if (ids.length > 1) ids.forEach((id) => dupIds.add(id));
  }
  return dupIds;
}

export function extractHost(rawUrl) {
  const str = String(rawUrl || '').trim();
  if (!str) return '';
  try {
    const withProto = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(str) ? str : `https://${str}`;
    const u = new URL(withProto);
    return u.hostname.replace(/^www\./i, '').toLowerCase();
  } catch {
    return str.toLowerCase();
  }
}
