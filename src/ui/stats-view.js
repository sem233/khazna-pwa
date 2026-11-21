/**
 * Khazna Pure SVG/CSS Statistics & Local Security Audit Dashboard
 *
 * - Animated counters for totals (passwords / cards / notes / health score)
 * - Pure SVG animated Donut Chart + Section Bars (tap any slice or bar to open that section!)
 * - Offline Security Audit: weak, reused, old (> 180 days) passwords
 * - Last backup date + Vault size
 * - Zero chart libraries, zero inline styles
 */

import { computeVaultAuditAndStats } from '../domain/audit.js';
import { t } from '../i18n/strings.js';
import { animateCounter, el, svgEl } from './dom.js';

function formatBytes(bytes) {
  if (!bytes || bytes < 1024) return `${bytes || 0} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function renderStatsView({
  session,
  lang,
  sections,
  passwords,
  cards,
  notes,
  vaultSizeBytes = 0,
  onOpenSection,
  onOpenBackup,
}) {
  const container = el('div', { class: 'settings-group view-enter' });
  const stats = computeVaultAuditAndStats({ sections, passwords, cards, notes });

  // Weekly backup reminder check
  const lastBackup = session.settings?.lastBackupAt;
  const daysSinceBackup = lastBackup
    ? Math.floor((Date.now() - Date.parse(lastBackup)) / (24 * 60 * 60 * 1000))
    : Infinity;
  if (daysSinceBackup >= (session.settings?.backupReminderDays ?? 7) && stats.totals.all > 0) {
    container.appendChild(
      el(
        'div',
        { class: 'banner banner-warn' },
        el('span', null, t(lang, 'backupReminderBanner')),
        el('button', { type: 'button', class: 'btn btn-sm btn-primary', onClick: onOpenBackup }, t(lang, 'tabExport'))
      )
    );
  }

  // --- Animated KPI Totals ---
  const mkKpi = (label, value, suffix = '') => {
    const numNode = el('span', { class: 'kpi-num ltr-inline' }, '0');
    animateCounter(numNode, value);
    return el(
      'div',
      { class: 'kpi-box stagger-item' },
      el('div', null, numNode, suffix ? el('span', { class: 'kpi-label' }, suffix) : null),
      el('span', { class: 'kpi-label' }, label)
    );
  };

  container.appendChild(
    el(
      'section',
      { class: 'stats-kpi-grid', 'aria-label': t(lang, 'statsTitle') },
      mkKpi(t(lang, 'totalPasswords'), stats.totals.passwords),
      mkKpi(t(lang, 'totalCards'), stats.totals.cards),
      mkKpi(t(lang, 'totalNotes'), stats.totals.notes),
      mkKpi(t(lang, 'securityScore'), stats.audit.healthScore, '%')
    )
  );

  // --- Animated SVG Donut Chart + Section Bars ---
  const radius = 74;
  const circumference = 2 * Math.PI * radius;
  const donutSvg = svgEl('svg', {
    class: 'donut-svg',
    viewBox: '0 0 200 200',
    role: 'img',
    'aria-label': t(lang, 'bySectionTitle'),
  });

  // Base ring track
  donutSvg.appendChild(
    svgEl('circle', {
      cx: 100,
      cy: 100,
      r: radius,
      fill: 'none',
      stroke: 'rgba(148, 163, 184, 0.16)',
      'stroke-width': 24,
    })
  );

  const totalPwd = stats.totals.passwords;
  let offset = 0;

  if (totalPwd > 0) {
    for (const item of stats.bySection) {
      if (item.count === 0) continue;
      const fraction = item.count / totalPwd;
      const segLen = Math.max(2, fraction * circumference);
      const circle = svgEl('circle', {
        class: 'donut-slice',
        cx: 100,
        cy: 100,
        r: radius,
        fill: 'none',
        stroke: item.color || '#38bdf8',
        'stroke-width': 24,
        'stroke-dasharray': `${segLen} ${circumference}`,
        'stroke-dashoffset': String(-offset),
        tabindex: '0',
        role: 'button',
        'aria-label': `${item.name}: ${item.count}`,
      });
      circle.addEventListener('click', () => {
        if (item.id !== 'uncategorized') onOpenSection(item.id);
      });
      donutSvg.appendChild(circle);
      offset += segLen;
    }
  }

  const barsWrap = el('div', { class: 'section-bars' });
  const maxCount = Math.max(1, ...stats.bySection.map((s) => s.count));

  for (const item of stats.bySection) {
    const pct = Math.round((item.count / maxCount) * 100);
    const barSvg = svgEl(
      'svg',
      { class: 'section-bar-svg', viewBox: '0 0 100 8', preserveAspectRatio: 'none', 'aria-hidden': 'true' },
      svgEl('rect', { x: 0, y: 0, width: 100, height: 8, rx: 4, fill: 'rgba(148,163,184,0.18)' }),
      svgEl('rect', { x: 0, y: 0, width: pct, height: 8, rx: 4, fill: item.color || '#38bdf8' })
    );

    const secBtn = el(
      'button',
      {
        type: 'button',
        class: 'section-bar-btn',
        onClick: () => {
          if (item.id !== 'uncategorized') onOpenSection(item.id);
        },
      },
      el(
        'div',
        { class: 'section-bar-top' },
        el('span', null, `${item.emoji} ${lang === 'en' && item.nameEn ? item.nameEn : item.name}`),
        el('span', { class: 'mono' }, String(item.count))
      ),
      barSvg
    );
    barsWrap.appendChild(secBtn);
  }

  container.appendChild(
    el(
      'section',
      { class: 'glass-card settings-group' },
      el('div', null, el('h2', { class: 'sheet-title' }, t(lang, 'bySectionTitle')), el('p', { class: 'settings-row-desc' }, t(lang, 'bySectionHint'))),
      el(
        'div',
        { class: 'stats-charts-grid' },
        el(
          'div',
          { class: 'donut-wrap' },
          donutSvg,
          el(
            'div',
            { class: 'donut-center' },
            el('strong', { class: 'kpi-num' }, String(totalPwd)),
            el('span', { class: 'kpi-label' }, t(lang, 'totalPasswords'))
          )
        ),
        barsWrap
      )
    )
  );

  // --- Local Security Audit ---
  const mkAuditBox = (title, count, cls, items) => {
    return el(
      'div',
      { class: `glass-card glass-card-compact settings-group ${cls}` },
      el('div', { class: 'section-bar-top' }, el('span', null, title), el('strong', { class: 'mono' }, String(count))),
      items.length > 0
        ? el(
            'div',
            { class: 'settings-row-desc' },
            items.slice(0, 4).map((x) => x.data?.title || x.entry?.data?.title || '').filter(Boolean).join(' • ')
          )
        : el('span', { class: 'settings-row-desc' }, lang === 'en' ? 'All clear ✓' : 'ممتاز ✓')
    );
  };

  container.appendChild(
    el(
      'section',
      { class: 'glass-card settings-group' },
      el('h2', { class: 'sheet-title' }, t(lang, 'securityScore')),
      el('p', { class: 'settings-row-desc' }, t(lang, 'auditOfflineNote')),
      el(
        'div',
        { class: 'audit-grid' },
        mkAuditBox(t(lang, 'auditWeak'), stats.audit.weak.length, stats.audit.weak.length ? 'banner-danger' : 'banner-success', stats.audit.weak),
        mkAuditBox(t(lang, 'auditReused'), stats.audit.reusedCount, stats.audit.reusedCount ? 'banner-warn' : 'banner-success', stats.audit.reusedGroups.flat()),
        mkAuditBox(t(lang, 'auditOld'), stats.audit.old.length, stats.audit.old.length ? 'banner-warn' : 'banner-success', stats.audit.old)
      )
    )
  );

  // --- Backup Date & Vault Size ---
  const lastBackupText = lastBackup
    ? new Date(lastBackup).toLocaleString(lang === 'en' ? 'en' : 'ar')
    : t(lang, 'neverBackedUp');

  container.appendChild(
    el(
      'section',
      { class: 'glass-card' },
      el(
        'div',
        { class: 'settings-row' },
        el('span', { class: 'settings-row-title' }, t(lang, 'lastBackupLabel')),
        el('span', { class: 'settings-row-desc' }, lastBackupText)
      ),
      el(
        'div',
        { class: 'settings-row' },
        el('span', { class: 'settings-row-title' }, t(lang, 'vaultSizeLabel')),
        el('span', { class: 'settings-row-desc ltr-inline mono' }, formatBytes(vaultSizeBytes))
      )
    )
  );

  return container;
}
