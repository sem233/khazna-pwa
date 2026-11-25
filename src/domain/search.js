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
 * - Duplicates match STRICTLY when BOTH username AND password are identical.
 * - When sectionId === 'all', duplicates are detected across ALL sections (cross-section + same-section).
 * - When a specific sectionId is selected, duplicates are detected strictly inside that section.
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
  const dupAnalysis = duplicatesOnly
    ? analyzeDuplicateGroups(entries, { scopeSectionId: sectionId })
    : null;

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
    if (dupAnalysis) {
      const ka = dupAnalysis.groupKeyByEntryId.get(a.id) || '';
      const kb = dupAnalysis.groupKeyByEntryId.get(b.id) || '';
      const grpCmp = ka.localeCompare(kb);
      if (grpCmp !== 0) return grpCmp;
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
 * Builds the strict exact-duplicate key: BOTH normalized username AND exact password must match.
 * Returns null if username is empty (so empty entries or password-only matches are never flagged).
 */
export function getExactCredentialKey(entry) {
  const d = entry?.data || {};
  const normUser = normalizeSearchText(d.username);
  const pwd = String(d.password || '');
  if (!normUser) return null;
  return `${normUser}\u0000${pwd}`;
}

/**
 * Groups duplicate entries strictly by identical (username + password).
 *
 * - scopeSectionId === 'all': groups duplicates across ALL sections (including cross-section duplicates!).
 * - scopeSectionId === <id>: groups duplicates strictly inside that single section.
 *
 * Also computes `countBySection` (exact duplicate count strictly inside each individual section)
 * so every section tile shows its own internal duplicate count, while `globalTotalCount` shows
 * all duplicates across all sections for the "All / إجمالي الحسابات" view.
 */
export function analyzeDuplicateGroups(entries, { scopeSectionId = 'all' } = {}) {
  const scopedEntries =
    scopeSectionId && scopeSectionId !== 'all'
      ? entries.filter((e) => (e.data?.sectionId || 'uncategorized') === scopeSectionId)
      : entries;

  const map = new Map();
  for (const entry of scopedEntries) {
    const key = getExactCredentialKey(entry);
    if (!key) continue;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(entry);
  }

  const groups = [];
  const duplicateIds = new Set();
  const groupKeyByEntryId = new Map();

  for (const [key, list] of map.entries()) {
    if (list.length < 2) continue;
    // Sort entries inside each duplicate group: newest updated first so the first item is the freshest copy
    const sorted = [...list].sort((a, b) =>
      String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''))
    );
    const sectionIds = [...new Set(sorted.map((e) => e.data?.sectionId || 'uncategorized'))];
    const group = {
      key,
      username: sorted[0].data?.username || '',
      hasPassword: Boolean(sorted[0].data?.password),
      entries: sorted,
      sectionIds,
      isCrossSection: sectionIds.length > 1,
    };
    groups.push(group);
    for (const e of sorted) {
      duplicateIds.add(e.id);
      groupKeyByEntryId.set(e.id, key);
    }
  }

  // Sort groups: cross-section duplicates first when in 'all' view, then largest group first
  groups.sort((a, b) => {
    if (a.isCrossSection !== b.isCrossSection) return a.isCrossSection ? -1 : 1;
    return b.entries.length - a.entries.length;
  });

  // Also compute internal duplicate count strictly inside each section (for individual section tiles)
  const countBySection = new Map();
  const perSecBuckets = new Map();
  for (const entry of entries) {
    const sid = entry.data?.sectionId || 'uncategorized';
    const key = getExactCredentialKey(entry);
    if (!key) continue;
    const secKey = `${sid}\u0001${key}`;
    if (!perSecBuckets.has(secKey)) perSecBuckets.set(secKey, { sid, count: 0 });
    perSecBuckets.get(secKey).count++;
  }
  for (const { sid, count } of perSecBuckets.values()) {
    if (count >= 2) {
      countBySection.set(sid, (countBySection.get(sid) || 0) + count);
    }
  }

  // Compute global duplicate count across ALL sections (for the "All Accounts" tile)
  const globalBuckets = new Map();
  for (const entry of entries) {
    const key = getExactCredentialKey(entry);
    if (!key) continue;
    globalBuckets.set(key, (globalBuckets.get(key) || 0) + 1);
  }
  let globalTotalCount = 0;
  for (const cnt of globalBuckets.values()) {
    if (cnt >= 2) globalTotalCount += cnt;
  }

  return {
    groups,
    duplicateIds,
    groupKeyByEntryId,
    countBySection,
    globalTotalCount,
    totalCount: duplicateIds.size,
  };
}

/**
 * Backward-compatible alias returning per-section/global duplicate analysis.
 */
export function analyzeSectionDuplicates(entries, opts = {}) {
  return analyzeDuplicateGroups(entries, opts);
}

/**
 * Backward-compatible helper returning the Set of exact duplicate entry IDs (same username + password).
 */
export function findDuplicateEntryIds(entries, scopeSectionId = 'all') {
  return analyzeDuplicateGroups(entries, { scopeSectionId }).duplicateIds;
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
