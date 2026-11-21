/**
 * Khazna Guided Import Transaction Manager
 *
 * - Generates a rich preview (counts, duplicate matches, warnings, detected folders)
 * - Supports target section selection OR mapping source folders to new/existing sections
 * - Supports duplicate strategies: 'skip' | 'replace' | 'keep-both'
 * - Commits atomically via VaultStorage.atomicOperationWithSnapshot() so the entire import
 *   can be undone in one click from the automatic encrypted snapshot
 */

import { extractHost, normalizeSearchText } from '../domain/search.js';
import { randomId } from '../crypto/utils.js';

const SECTION_ACCENTS = ['#38bdf8', '#10b981', '#a78bfa', '#f59e0b', '#f472b6', '#2dd4bf', '#fb7185'];

function passwordMatchKey(item) {
  const host = extractHost(item.url);
  const user = normalizeSearchText(item.username);
  const title = normalizeSearchText(item.title);
  if (host && user) return `u:${host}|${user}`;
  return `t:${title}|${user}`;
}

function cardMatchKey(card) {
  const num = String(card.number || '').replace(/\D+/g, '');
  const label = normalizeSearchText(card.cardName);
  return num.length >= 4 ? `c:${num.slice(0, 6)}|${num.slice(-4)}|${card.expiry || ''}` : `cl:${label}`;
}

function noteMatchKey(note) {
  return `n:${normalizeSearchText(note.title)}|${normalizeSearchText((note.body || '').slice(0, 80))}`;
}

/**
 * Computes an import preview comparing the parsed bundle against existing decrypted records.
 */
export function buildImportPreview(bundle, existing = { sections: [], passwords: [], cards: [], notes: [] }) {
  const existingPwdKeys = new Map();
  for (const p of existing.passwords) {
    existingPwdKeys.set(passwordMatchKey(p.data || {}), p);
  }

  const existingCardKeys = new Map();
  for (const c of existing.cards) {
    existingCardKeys.set(cardMatchKey(c.data || {}), c);
  }

  const existingNoteKeys = new Map();
  for (const n of existing.notes) {
    existingNoteKeys.set(noteMatchKey(n.data || {}), n);
  }

  let duplicatePasswords = 0;
  for (const p of bundle.passwords || []) {
    if (existingPwdKeys.has(passwordMatchKey(p))) duplicatePasswords++;
  }

  let duplicateCards = 0;
  for (const c of bundle.cards || []) {
    if (existingCardKeys.has(cardMatchKey(c))) duplicateCards++;
  }

  let duplicateNotes = 0;
  for (const n of bundle.notes || []) {
    if (existingNoteKeys.has(noteMatchKey(n))) duplicateNotes++;
  }

  const detectedFolders = new Set();
  for (const s of bundle.sections || []) {
    if (s?.name) detectedFolders.add(s.name);
  }
  for (const p of bundle.passwords || []) {
    if (p?.folder) detectedFolders.add(p.folder);
  }

  return {
    format: bundle.format,
    counts: {
      passwords: (bundle.passwords || []).length,
      cards: (bundle.cards || []).length,
      notes: (bundle.notes || []).length,
      sections: detectedFolders.size,
    },
    duplicates: {
      passwords: duplicatePasswords,
      cards: duplicateCards,
      notes: duplicateNotes,
      total: duplicatePasswords + duplicateCards + duplicateNotes,
    },
    folders: Array.from(detectedFolders),
    warnings: bundle.warnings || [],
    csvHeaders: bundle.csvHeaders || null,
    csvColumnMap: bundle.csvColumnMap || null,
  };
}

/**
 * Commits a parsed bundle atomically with an automatic encrypted snapshot for instant Undo.
 *
 * @param {object} opts
 * @param {import('../auth/session.js').VaultSession} opts.session
 * @param {object} opts.bundle Output of parseImportSource()
 * @param {'map-folders'|'single-section'} [opts.sectionMode='map-folders']
 * @param {string|null} [opts.targetSectionId=null]
 * @param {'skip'|'replace'|'keep-both'} [opts.duplicateStrategy='skip']
 */
export async function commitImportTransaction({
  session,
  bundle,
  sectionMode = 'map-folders',
  targetSectionId = null,
  duplicateStrategy = 'skip',
}) {
  const existingSections = await session.listRecords('section');
  const existingPasswords = await session.listRecords('password');
  const existingCards = await session.listRecords('card');
  const existingNotes = await session.listRecords('note');

  const sectionByName = new Map(
    existingSections.map((s) => [normalizeSearchText(s.data?.name), s.id])
  );
  const existingPwdByKey = new Map(
    existingPasswords.map((p) => [passwordMatchKey(p.data || {}), p])
  );
  const existingCardByKey = new Map(
    existingCards.map((c) => [cardMatchKey(c.data || {}), c])
  );
  const existingNoteByKey = new Map(
    existingNotes.map((n) => [noteMatchKey(n.data || {}), n])
  );

  const itemsToEncrypt = [];
  let nextSectionOrder = existingSections.length;
  const fallbackSectionId = targetSectionId || existingSections[0]?.id || null;

  const resolveFolderSectionId = (folderName, sectionMeta = null) => {
    if (sectionMode === 'single-section') {
      return fallbackSectionId;
    }
    const clean = String(folderName || '').trim();
    if (!clean) return fallbackSectionId;
    const norm = normalizeSearchText(clean);
    if (sectionByName.has(norm)) return sectionByName.get(norm);

    const newId = randomId('sec');
    sectionByName.set(norm, newId);
    itemsToEncrypt.push({
      id: newId,
      type: 'section',
      data: {
        name: clean,
        emoji: sectionMeta?.emoji || '📁',
        color: sectionMeta?.color || SECTION_ACCENTS[nextSectionOrder % SECTION_ACCENTS.length],
        order: nextSectionOrder++,
      },
    });
    return newId;
  };

  // Pre-create explicitly listed sections when mapping folders
  if (sectionMode === 'map-folders') {
    for (const sec of bundle.sections || []) {
      if (sec?.name) resolveFolderSectionId(sec.name, sec);
    }
  }

  const report = {
    added: { sections: 0, passwords: 0, cards: 0, notes: 0 },
    replaced: { passwords: 0, cards: 0, notes: 0 },
    skipped: { passwords: 0, cards: 0, notes: 0 },
    snapshotId: null,
  };

  // 1) Passwords
  for (const p of bundle.passwords || []) {
    const key = passwordMatchKey(p);
    const existing = existingPwdByKey.get(key);
    const secId = resolveFolderSectionId(p.folder || p.sectionName || '');

    const payload = {
      title: String(p.title || 'Untitled').trim(),
      sectionId: secId,
      username: String(p.username || ''),
      password: String(p.password || ''),
      url: String(p.url || ''),
      notes: String(p.notes || ''),
      favorite: Boolean(p.favorite),
      passwordUpdatedAt: p.updatedAt || new Date().toISOString(),
      passwordHistory: Array.isArray(p.passwordHistory) ? p.passwordHistory.slice(0, 10) : [],
    };

    if (existing) {
      if (duplicateStrategy === 'skip') {
        report.skipped.passwords++;
        continue;
      }
      if (duplicateStrategy === 'replace') {
        const hist = Array.isArray(existing.data?.passwordHistory) ? [...existing.data.passwordHistory] : [];
        if (existing.data?.password && existing.data.password !== payload.password) {
          hist.unshift({ value: existing.data.password, changedAt: new Date().toISOString() });
        }
        payload.passwordHistory = hist.slice(0, 10);
        itemsToEncrypt.push({
          id: existing.id,
          type: 'password',
          data: payload,
          createdAt: existing.createdAt,
        });
        report.replaced.passwords++;
        continue;
      }
    }

    itemsToEncrypt.push({
      id: randomId('pwd'),
      type: 'password',
      data: payload,
      createdAt: p.createdAt,
    });
    report.added.passwords++;
  }

  // 2) Cards
  for (const c of bundle.cards || []) {
    const key = cardMatchKey(c);
    const existing = existingCardByKey.get(key);
    const payload = {
      cardName: String(c.cardName || 'Card').trim(),
      bankName: String(c.bankName || ''),
      holderName: String(c.holderName || ''),
      number: String(c.number || ''),
      expiry: String(c.expiry || ''),
      cvv: String(c.cvv || ''),
      pin: String(c.pin || ''),
      notes: String(c.notes || ''),
      theme: c.theme || 'obsidian',
      brandOverride: c.brandOverride || 'auto',
      partial: Boolean(c.partial || String(c.number || '').includes('*')),
    };

    if (existing) {
      if (duplicateStrategy === 'skip') {
        report.skipped.cards++;
        continue;
      }
      if (duplicateStrategy === 'replace') {
        itemsToEncrypt.push({ id: existing.id, type: 'card', data: payload, createdAt: existing.createdAt });
        report.replaced.cards++;
        continue;
      }
    }

    itemsToEncrypt.push({ id: randomId('crd'), type: 'card', data: payload });
    report.added.cards++;
  }

  // 3) Notes
  for (const n of bundle.notes || []) {
    const key = noteMatchKey(n);
    const existing = existingNoteByKey.get(key);
    const payload = {
      title: String(n.title || 'Note').trim(),
      body: String(n.body || ''),
      checklist: Array.isArray(n.checklist) ? n.checklist : [],
      pinned: Boolean(n.pinned),
    };

    if (existing) {
      if (duplicateStrategy === 'skip') {
        report.skipped.notes++;
        continue;
      }
      if (duplicateStrategy === 'replace') {
        itemsToEncrypt.push({ id: existing.id, type: 'note', data: payload, createdAt: existing.createdAt });
        report.replaced.notes++;
        continue;
      }
    }

    itemsToEncrypt.push({ id: randomId('nte'), type: 'note', data: payload });
    report.added.notes++;
  }

  report.added.sections = itemsToEncrypt.filter((i) => i.type === 'section').length;

  const encryptedBatch = await session.encryptBatchForAtomicWrite(itemsToEncrypt);
  const snapshotId = await session.storage.atomicOperationWithSnapshot({
    reason: `import-${bundle.format}`,
    putRecords: encryptedBatch,
  });

  report.snapshotId = snapshotId;
  return report;
}
