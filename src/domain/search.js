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
 * - Duplicates are strictly analyzed PER SECTION so each section identifies its own real duplicates.
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
  const dupAnalysis = duplicatesOnly ? analyzeSectionDuplicates(entries) : null;

  const filtered = entries.filter((entry) => {
    const d = entry.data || {};
    if (sectionId && sectionId !== 'all' && d.sectionId !== sectionId) return false;
    if (favoritesOnly && !d.favorite) return false;
    if (dupAnalysis && !dupAnalysis.duplicateIds.has(entry.id)) return false;
    if (query) {
      return matchesQuery(query, [d.title, d.username, d.url, d.notes]);
    }
    return true;
  });

  filtered.sort((a, b) => {
    const da = a.data || {};
    const db = b.data || {};
    // When viewing duplicates, group identical duplicate clusters side-by-side within each section
    if (dupAnalysis) {
      const ia = dupAnalysis.byEntryId.get(a.id);
      const ib = dupAnalysis.byEntryId.get(b.id);
      const secCmp = String(ia?.sectionId || '').localeCompare(String(ib?.sectionId || ''));
      if (secCmp !== 0) return secCmp;
      const clusterCmp = String(ia?.clusterKey || '').localeCompare(String(ib?.clusterKey || ''));
      if (clusterCmp !== 0) return clusterCmp;
    }
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
 * Practical Per-Section Duplicate Analyzer.
 * Checks strictly WITHIN each section for real duplicates:
 * 1. Same normalized username / email / bill number (length >= 2)
 * 2. Same non-empty password (length >= 3)
 * 3. Same normalized title (length >= 2)
 *
 * Returns:
 * - byEntryId: Map<id, { sectionId, reasons: Array<{ type, count, clusterKey }>, clusterKey }>
 * - countBySection: Map<sectionId, number>
 * - duplicateIds: Set<id>
 * - totalCount: number
 */
export function analyzeSectionDuplicates(entries) {
  const bySection = new Map();
  for (const entry of entries) {
    const sid = entry.data?.sectionId || 'uncategorized';
    if (!bySection.has(sid)) bySection.set(sid, []);
    bySection.get(sid).push(entry);
  }

  const byEntryId = new Map();
  const countBySection = new Map();
  const duplicateIds = new Set();

  const registerReason = (entryId, sectionId, reason) => {
    duplicateIds.add(entryId);
    let info = byEntryId.get(entryId);
    if (!info) {
      info = { sectionId, reasons: [], clusterKey: reason.clusterKey };
      byEntryId.set(entryId, info);
    }
    if (!info.reasons.some((r) => r.type === reason.type)) {
      info.reasons.push(reason);
    }
  };

  for (const [sid, list] of bySection.entries()) {
    const byUser = new Map();
    const byPwd = new Map();
    const byTitle = new Map();

    for (const entry of list) {
      const d = entry.data || {};
      const normUser = normalizeSearchText(d.username);
      const pwd = String(d.password || '');
      const normTitle = normalizeSearchText(d.title);

      if (normUser.length >= 2) {
        if (!byUser.has(normUser)) byUser.set(normUser, []);
        byUser.get(normUser).push(entry.id);
      }
      if (pwd.length >= 3) {
        if (!byPwd.has(pwd)) byPwd.set(pwd, []);
        byPwd.get(pwd).push(entry.id);
      }
      if (normTitle.length >= 2) {
        if (!byTitle.has(normTitle)) byTitle.set(normTitle, []);
        byTitle.get(normTitle).push(entry.id);
      }
    }

    const secDupIds = new Set();

    for (const [key, ids] of byUser.entries()) {
      if (ids.length > 1) {
        for (const id of ids) {
          secDupIds.add(id);
          registerReason(id, sid, { type: 'username', count: ids.length, clusterKey: `1-user:${key}` });
        }
      }
    }
    for (const [key, ids] of byPwd.entries()) {
      if (ids.length > 1) {
        for (const id of ids) {
          secDupIds.add(id);
          registerReason(id, sid, { type: 'password', count: ids.length, clusterKey: `2-pwd:${key}` });
        }
      }
    }
    for (const [key, ids] of byTitle.entries()) {
      if (ids.length > 1) {
        for (const id of ids) {
          secDupIds.add(id);
          registerReason(id, sid, { type: 'title', count: ids.length, clusterKey: `3-title:${key}` });
        }
      }
    }

    if (secDupIds.size > 0) {
      countBySection.set(sid, secDupIds.size);
    }
  }

  return {
    byEntryId,
    countBySection,
    duplicateIds,
    totalCount: duplicateIds.size,
  };
}

/**
 * Backward-compatible helper returning the Set of per-section duplicate entry IDs.
 */
export function findDuplicateEntryIds(entries) {
  return analyzeSectionDuplicates(entries).duplicateIds;
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
