/**
 * Khazna Local Security Audit & Vault Statistics
 *
 * 100% offline — zero network breach checks.
 * Computes weak passwords, reused passwords, old passwords (> 180 days),
 * per-section distributions, and overall vault health score.
 */

import { evaluatePasswordStrength } from '../crypto/vault-crypto.js';

export const OLD_PASSWORD_DAYS = 180;

export function computeVaultAuditAndStats({
  sections = [],
  passwords = [],
  cards = [],
  notes = [],
  now = Date.now(),
}) {
  const weak = [];
  const reusedMap = new Map();
  const old = [];
  const oldCutoffMs = now - OLD_PASSWORD_DAYS * 24 * 60 * 60 * 1000;

  for (const entry of passwords) {
    const d = entry.data || {};
    const pwd = String(d.password || '');
    const strength = evaluatePasswordStrength(pwd);

    if (strength.score <= 1) {
      weak.push({ entry, strength });
    }

    if (pwd.length > 0) {
      const bucket = reusedMap.get(pwd) || [];
      bucket.push(entry);
      reusedMap.set(pwd, bucket);
    }

    const changedAt = Date.parse(d.passwordUpdatedAt || entry.updatedAt || entry.createdAt || '');
    if (!Number.isNaN(changedAt) && changedAt < oldCutoffMs) {
      const ageDays = Math.floor((now - changedAt) / (24 * 60 * 60 * 1000));
      old.push({ entry, ageDays });
    }
  }

  const reusedGroups = [];
  const reusedEntryIds = new Set();
  for (const list of reusedMap.values()) {
    if (list.length > 1) {
      reusedGroups.push(list);
      for (const e of list) reusedEntryIds.add(e.id);
    }
  }

  // Passwords per section breakdown
  const sectionCounts = new Map();
  for (const sec of sections) {
    sectionCounts.set(sec.id, {
      id: sec.id,
      name: sec.data?.name || '',
      emoji: sec.data?.emoji || '📁',
      color: sec.data?.color || '#38bdf8',
      count: 0,
    });
  }
  let uncategorizedCount = 0;

  for (const entry of passwords) {
    const sid = entry.data?.sectionId;
    if (sid && sectionCounts.has(sid)) {
      sectionCounts.get(sid).count += 1;
    } else {
      uncategorizedCount += 1;
    }
  }

  const bySection = Array.from(sectionCounts.values()).sort((a, b) => b.count - a.count);
  if (uncategorizedCount > 0) {
    bySection.push({
      id: 'uncategorized',
      name: 'غير مصنّف',
      nameEn: 'Uncategorized',
      emoji: '📂',
      color: '#94a3b8',
      count: uncategorizedCount,
    });
  }

  // Health score 0..100
  const totalPwd = passwords.length;
  let healthScore = 100;
  if (totalPwd > 0) {
    const weakPenalty = (weak.length / totalPwd) * 50;
    const reusedPenalty = (reusedEntryIds.size / totalPwd) * 35;
    const oldPenalty = (old.length / totalPwd) * 15;
    healthScore = Math.max(0, Math.round(100 - weakPenalty - reusedPenalty - oldPenalty));
  }

  return {
    totals: {
      passwords: passwords.length,
      cards: cards.length,
      notes: notes.length,
      sections: sections.length,
      all: passwords.length + cards.length + notes.length,
    },
    bySection,
    audit: {
      healthScore,
      weak,
      reusedGroups,
      reusedCount: reusedEntryIds.size,
      old,
    },
  };
}
