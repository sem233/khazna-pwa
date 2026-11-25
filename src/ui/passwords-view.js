/**
 * Khazna Passwords & Sections Dashboard View (Glassmorphism Multi-Column Grid)
 *
 * Features:
 * - Top Glass KPI Strip (Total Accounts + Top 3 Sections)
 * - Wrapping Centered Section Pills (ALL sections always visible, never clipped off-screen)
 * - Radiant Golden-Glowing Favorite Cards (always pinned to the top of their section)
 * - Clean Glass Cards with outside Eye reveal toggle + instant Copy buttons for Username & Password
 * - Optional Password (Bills / numbers work without entering a password) & ZERO URL field clutter
 * - Full Section Management (Create, Rename, Theme, Emoji, Reorder ↑↓, Delete) & Multi-Select Bulk Move
 */

import { evaluatePasswordStrength } from '../crypto/vault-crypto.js';
import { analyzeSectionDuplicates, filterAndSortPasswords } from '../domain/search.js';
import { formatError, t } from '../i18n/strings.js';
import {
  accentClassForHex,
  el,
  openBottomSheet,
  pickNextUnusedSectionTheme,
  SECTION_COLOR_OPTIONS,
  showToast,
  svgIcon,
  triggerHaptic,
} from './dom.js';
import { openGeneratorSheet } from './generator-sheet.js';

const SECTION_EMOJIS = ['🔐', '🧾', '🏦', '💬', '💼', '🌐', '📱', '🛒', '🎮', '☁️', '🏠', '✈️', '🏥', '🎓', '🎵', '⚡'];

export function renderPasswordsView({
  session,
  lang,
  sections,
  passwords,
  trashedPasswords,
  state,
  onStateChange,
  onRefresh,
}) {
  const container = el('div', { class: 'vault-dashboard view-enter' });

  const copyField = async (value, label) => {
    if (!value) return;
    try {
      const clearSec = session.settings?.clipboardClearSec ?? 30;
      await session.clipboard.copySecret(value, clearSec);
      triggerHaptic();
      showToast(`${t(lang, 'copiedToast')}: ${label}`, 'success');
    } catch (err) {
      showToast(formatError(err, lang), 'error');
    }
  };

  const sectionById = new Map(sections.map((s) => [s.id, s]));
  const countBySec = new Map();
  for (const p of passwords) {
    const sid = p.data?.sectionId || 'uncategorized';
    countBySec.set(sid, (countBySec.get(sid) || 0) + 1);
  }
  const sortedSections = [...sections].sort((a, b) => (a.data?.order ?? 0) - (b.data?.order ?? 0));

  // Practical Per-Section Duplicate Analysis (computed strictly within each section)
  const dupAnalysis = analyzeSectionDuplicates(passwords);
  const activeDupCount =
    state.sectionId && state.sectionId !== 'all'
      ? dupAnalysis.countBySection.get(state.sectionId) || 0
      : dupAnalysis.totalCount;

  // --- 1) Equal-Sized Uniform Glass Grid for ALL Sections (Distinct Theme per Section!) ---
  const secGrid = el('section', {
    class: 'section-grid-equal',
    role: 'tablist',
    'aria-label': t(lang, 'manageSections'),
  });

  // "All Accounts" equal tile
  const isAllActive =
    !state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && state.sectionId === 'all';
  secGrid.appendChild(
    el(
      'button',
      {
        type: 'button',
        role: 'tab',
        'aria-selected': isAllActive ? 'true' : 'false',
        class: `sec-tile accent-sky ${isAllActive ? 'is-active' : ''}`.trim(),
        onClick: () =>
          onStateChange({ sectionId: 'all', showTrash: false, favoritesOnly: false, duplicatesOnly: false }),
      },
      el(
        'div',
        { class: 'sec-tile-top' },
        el('span', { class: 'sec-tile-name' }, `✨ ${t(lang, 'totalAccountsKpi')}`),
        dupAnalysis.totalCount > 0
          ? el('span', { class: 'sec-tile-dup', title: t(lang, 'duplicates') }, `⚠ ${dupAnalysis.totalCount}`)
          : null
      ),
      el('strong', { class: 'sec-tile-num ltr-inline' }, String(passwords.length))
    )
  );

  // Every user section rendered at 100% EQUAL size with its own distinct glass theme
  for (const sec of sortedSections) {
    const d = sec.data || {};
    const accentCls = accentClassForHex(d.color);
    const isAct = !state.showTrash && state.sectionId === sec.id;
    const secDupCount = dupAnalysis.countBySection.get(sec.id) || 0;

    secGrid.appendChild(
      el(
        'button',
        {
          type: 'button',
          role: 'tab',
          'aria-selected': isAct ? 'true' : 'false',
          class: `sec-tile ${accentCls} ${isAct ? 'is-active' : ''}`.trim(),
          onClick: () =>
            onStateChange({ sectionId: sec.id, showTrash: false, favoritesOnly: false, duplicatesOnly: false }),
        },
        el(
          'div',
          { class: 'sec-tile-top' },
          el('span', { class: 'sec-tile-name' }, `${d.emoji || '📁'} ${d.name || ''}`),
          secDupCount > 0
            ? el('span', { class: 'sec-tile-dup', title: t(lang, 'duplicates') }, `⚠ ${secDupCount}`)
            : null
        ),
        el('strong', { class: 'sec-tile-num ltr-inline' }, String(countBySec.get(sec.id) || 0))
      )
    );
  }

  // Equal-sized "+ Manage Sections" tile
  secGrid.appendChild(
    el(
      'button',
      {
        type: 'button',
        class: 'sec-tile sec-tile-manage',
        'data-testid': 'manage-sections-btn',
        onClick: () => openManageSectionsSheet({ session, lang, sections: sortedSections, passwords, onRefresh }),
      },
      el('span', { class: 'sec-tile-manage-icon' }, svgIcon('plus', 18)),
      el('span', { class: 'sec-tile-name' }, t(lang, 'manageSectionsBtn'))
    )
  );

  container.appendChild(secGrid);

  // --- Filtered List (Favorites ALWAYS sorted to top; Duplicates grouped per section!) ---
  const sourceList = state.showTrash ? trashedPasswords : passwords;
  const visibleEntries = filterAndSortPasswords(sourceList, {
    query: state.query,
    sectionId: state.showTrash ? 'all' : state.sectionId,
    favoritesOnly: !state.showTrash && state.favoritesOnly,
    duplicatesOnly: !state.showTrash && state.duplicatesOnly,
    sortBy: state.sortBy,
  });

  // --- 2) Sub-Filters Row (All / Pinned Favorites / Per-Section Duplicates / Trash + Multi-Select + Sort) ---
  const scopedPasswords =
    state.sectionId && state.sectionId !== 'all'
      ? passwords.filter((p) => p.data?.sectionId === state.sectionId)
      : passwords;
  const favCount = scopedPasswords.filter((p) => p.data?.favorite).length;
  const selectedIds = state.selectedIds || new Set();
  const isSelecting = Boolean(state.selectMode) || selectedIds.size > 0;

  const sortSelect = el(
    'select',
    {
      class: 'select vault-sort-select',
      'aria-label': 'Sort',
      onChange: (e) => onStateChange({ sortBy: e.target.value }),
    },
    el('option', { value: 'updated-desc', selected: state.sortBy === 'updated-desc' }, t(lang, 'sortUpdated')),
    el('option', { value: 'title-asc', selected: state.sortBy === 'title-asc' }, t(lang, 'sortTitleAsc')),
    el('option', { value: 'created-desc', selected: state.sortBy === 'created-desc' }, t(lang, 'sortCreated'))
  );

  const subFilters = el(
    'div',
    { class: 'vault-sub-bar' },
    el(
      'div',
      { class: 'vault-sub-pills' },
      el(
        'button',
        {
          type: 'button',
          class: `sub-pill ${!state.showTrash && !state.favoritesOnly && !state.duplicatesOnly ? 'is-active' : ''}`.trim(),
          onClick: () => onStateChange({ showTrash: false, favoritesOnly: false, duplicatesOnly: false }),
        },
        t(lang, 'allSections')
      ),
      el(
        'button',
        {
          type: 'button',
          class: `sub-pill sub-pill-fav ${!state.showTrash && state.favoritesOnly ? 'is-active' : ''}`.trim(),
          onClick: () => onStateChange({ showTrash: false, favoritesOnly: !state.favoritesOnly, duplicatesOnly: false }),
        },
        `✦ ${t(lang, 'favorites')}`,
        favCount > 0 ? el('span', { class: 'sec-pill-count' }, String(favCount)) : null
      ),
      el(
        'button',
        {
          type: 'button',
          'data-testid': 'duplicates-filter-btn',
          class: `sub-pill sub-pill-dup ${!state.showTrash && state.duplicatesOnly ? 'is-active' : ''}`.trim(),
          onClick: () => onStateChange({ showTrash: false, favoritesOnly: false, duplicatesOnly: !state.duplicatesOnly }),
        },
        `⚠ ${t(lang, 'duplicates')}`,
        activeDupCount > 0 ? el('span', { class: 'sec-pill-count' }, String(activeDupCount)) : null
      ),
      el(
        'button',
        {
          type: 'button',
          class: `sub-pill ${state.showTrash ? 'is-active' : ''}`.trim(),
          onClick: () => onStateChange({ showTrash: !state.showTrash, favoritesOnly: false, duplicatesOnly: false }),
        },
        `🗑 ${t(lang, 'trash')}`,
        trashedPasswords.length > 0 ? el('span', { class: 'sec-pill-count' }, String(trashedPasswords.length)) : null
      )
    ),
    el(
      'div',
      { class: 'vault-sub-tools' },
      !state.showTrash && visibleEntries.length > 0 && !isSelecting
        ? el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm',
              'data-testid': 'multi-select-btn',
              onClick: () => onStateChange({ selectMode: true, selectedIds: new Set() }),
            },
            svgIcon('check', 14),
            t(lang, 'multiSelectBtn')
          )
        : null,
      sortSelect
    )
  );
  container.appendChild(subFilters);

  // Per-Section Duplicates Info Banner
  if (!state.showTrash && state.duplicatesOnly && visibleEntries.length > 0) {
    container.appendChild(
      el(
        'div',
        { class: 'banner banner-warn' },
        el(
          'span',
          null,
          state.sectionId && state.sectionId !== 'all'
            ? t(lang, 'dupBannerSection')
            : t(lang, 'dupBannerAll')
        )
      )
    );
  }

  // --- 4) Full-Width Glass "+ Add New Item" Bar & Search Bar ---
  if (!state.showTrash) {
    container.appendChild(
      el(
        'button',
        {
          type: 'button',
          class: 'vault-add-bar',
          onClick: () => {
            triggerHaptic(12);
            openPasswordEditorSheet({
              session,
              lang,
              sections: sortedSections,
              defaultSectionId: state.sectionId !== 'all' ? state.sectionId : null,
              onSaved: onRefresh,
            });
          },
        },
        svgIcon('plus', 18),
        el('span', null, t(lang, 'addNewToVaultBtn'))
      )
    );
  }

  const searchInput = el('input', {
    type: 'search',
    class: 'input vault-search-input',
    value: state.query || '',
    placeholder: t(lang, 'searchPlaceholder'),
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': t(lang, 'searchPlaceholder'),
    onInput: (e) => {
      onStateChange({ query: e.target.value }, { keepFocus: true });
    },
  });

  const genQuickBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-icon',
      'aria-label': t(lang, 'generatorTitle'),
      title: t(lang, 'generatorTitle'),
      onClick: () => openGeneratorSheet({ session, lang }),
    },
    svgIcon('key', 18)
  );

  container.appendChild(
    el(
      'div',
      { class: 'toolbar-row' },
      el('div', { class: 'search-wrap' }, el('span', { class: 'search-icon' }, svgIcon('search', 18)), searchInput),
      genQuickBtn
    )
  );

  // --- 5) Multi-Select Sticky Action Bar ---
  if (isSelecting && !state.showTrash) {
    const allVisibleSelected =
      visibleEntries.length > 0 && visibleEntries.every((e) => selectedIds.has(e.id));

    container.appendChild(
      el(
        'div',
        { class: 'multiselect-bar' },
        el(
          'div',
          { class: 'toolbar-row' },
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm',
              onClick: () => {
                if (allVisibleSelected) {
                  onStateChange({ selectMode: true, selectedIds: new Set() });
                } else {
                  onStateChange({
                    selectMode: true,
                    selectedIds: new Set(visibleEntries.map((e) => e.id)),
                  });
                }
              },
            },
            allVisibleSelected ? t(lang, 'deselectAllBtn') : t(lang, 'selectAllBtn')
          ),
          el('strong', null, `${selectedIds.size} ${t(lang, 'multiSelectCount')}`)
        ),
        el(
          'div',
          { class: 'toolbar-row' },
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm btn-primary',
              disabled: selectedIds.size === 0,
              onClick: () => {
                openBulkMoveSheet({
                  session,
                  lang,
                  selectedIds,
                  sections: sortedSections,
                  onStateChange,
                  onRefresh,
                });
              },
            },
            svgIcon('link', 14),
            t(lang, 'moveToSection')
          ),
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm btn-danger',
              disabled: selectedIds.size === 0,
              onClick: async () => {
                for (const id of selectedIds) {
                  await session.trashRecord(id);
                }
                onStateChange({ selectMode: false, selectedIds: new Set() });
                await onRefresh();
              },
            },
            svgIcon('trash', 15),
            t(lang, 'moveToTrash')
          ),
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm',
              onClick: () => onStateChange({ selectMode: false, selectedIds: new Set() }),
            },
            t(lang, 'cancelSelection')
          )
        )
      )
    );
  }

  // --- 6) Cards Grid ---
  const listWrap = el('div', { class: 'entry-list', 'data-testid': 'password-list' });

  if (visibleEntries.length === 0) {
    listWrap.appendChild(
      el(
        'div',
        { class: 'glass-card empty-state' },
        svgIcon(state.duplicatesOnly ? 'check' : 'lock', 36),
        el('h3', null, state.duplicatesOnly ? t(lang, 'dupNoneInSection') : t(lang, 'emptyPasswords')),
        state.duplicatesOnly ? null : el('p', null, t(lang, 'emptyPasswordsSub'))
      )
    );
    container.appendChild(listWrap);
    return container;
  }

  const isGrouped =
    state.sectionId === 'all' &&
    !state.showTrash &&
    !state.favoritesOnly &&
    !state.query;

  if (isGrouped) {
    const groups = new Map();
    const uncategorized = [];

    for (const entry of visibleEntries) {
      const sid = entry.data?.sectionId;
      if (sid && sectionById.has(sid)) {
        if (!groups.has(sid)) groups.set(sid, { section: sectionById.get(sid), entries: [] });
        groups.get(sid).entries.push(entry);
      } else {
        uncategorized.push(entry);
      }
    }

    for (const sec of sortedSections) {
      const g = groups.get(sec.id);
      if (!g || g.entries.length === 0) continue;
      const sd = sec.data || {};
      const accentCls = accentClassForHex(sd.color);

      const toggleArrow = el('span', { class: 'count-badge' }, '▼');
      const groupBody = el('div', { class: 'section-group-body vault-cards-grid' });
      for (const entry of g.entries) {
        groupBody.appendChild(
          buildEntryCard({
            entry,
            sectionById,
            selectedIds,
            state,
            session,
            lang,
            sortedSections,
            copyField,
            dupInfo: dupAnalysis.byEntryId.get(entry.id) || null,
            onStateChange,
            onRefresh,
          })
        );
      }

      const groupWrap = el('div', { class: `section-group ${accentCls}` });
      const groupHeader = el(
        'div',
        {
          class: 'section-group-header',
          onClick: () => {
            const isColl = groupWrap.classList.toggle('is-collapsed');
            toggleArrow.textContent = isColl ? '▲' : '▼';
          },
        },
        el(
          'div',
          { class: 'section-group-title-wrap' },
          el('span', { class: 'section-group-emoji' }, sd.emoji || '📁'),
          el('span', { class: 'section-group-title' }, sd.name || ''),
          el('span', { class: 'section-group-badge' }, String(g.entries.length))
        ),
        el('div', { class: 'section-group-actions' }, toggleArrow)
      );

      groupWrap.appendChild(groupHeader);
      groupWrap.appendChild(groupBody);
      listWrap.appendChild(groupWrap);
    }

    if (uncategorized.length > 0) {
      const groupBody = el('div', { class: 'section-group-body vault-cards-grid' });
      for (const entry of uncategorized) {
        groupBody.appendChild(
          buildEntryCard({
            entry,
            sectionById,
            selectedIds,
            state,
            session,
            lang,
            sortedSections,
            copyField,
            dupInfo: dupAnalysis.byEntryId.get(entry.id) || null,
            onStateChange,
            onRefresh,
          })
        );
      }
      const groupWrap = el('div', { class: 'section-group' });
      const toggleArrow = el('span', { class: 'count-badge' }, '▼');
      const groupHeader = el(
        'div',
        {
          class: 'section-group-header',
          onClick: () => {
            const isColl = groupWrap.classList.toggle('is-collapsed');
            toggleArrow.textContent = isColl ? '▲' : '▼';
          },
        },
        el(
          'div',
          { class: 'section-group-title-wrap' },
          el('span', { class: 'section-group-emoji' }, '📁'),
          el('span', { class: 'section-group-title' }, lang === 'en' ? 'Uncategorized' : 'غير مصنّف'),
          el('span', { class: 'section-group-badge' }, String(uncategorized.length))
        ),
        el('div', { class: 'section-group-actions' }, toggleArrow)
      );
      groupWrap.appendChild(groupHeader);
      groupWrap.appendChild(groupBody);
      listWrap.appendChild(groupWrap);
    }
  } else {
    const flatGrid = el('div', { class: 'vault-cards-grid' });
    for (const entry of visibleEntries) {
      flatGrid.appendChild(
        buildEntryCard({
          entry,
          sectionById,
          selectedIds,
          state,
          session,
          lang,
          sortedSections,
          copyField,
          dupInfo: dupAnalysis.byEntryId.get(entry.id) || null,
          onStateChange,
          onRefresh,
        })
      );
    }
    listWrap.appendChild(flatGrid);
  }

  container.appendChild(listWrap);
  return container;
}

function buildEntryCard({
  entry,
  sectionById,
  selectedIds,
  state,
  session,
  lang,
  sortedSections,
  copyField,
  dupInfo = null,
  onStateChange,
  onRefresh,
}) {
  const d = entry.data || {};
  const sec = sectionById.get(d.sectionId);
  const accentCls = accentClassForHex(sec?.data?.color);
  const isSelected = selectedIds.has(entry.id);
  const isPinned = Boolean(d.favorite);
  const isSelecting = (Boolean(state.selectMode) || selectedIds.size > 0) && !state.showTrash;

  const toggleThisSelection = () => {
    const next = new Set(selectedIds);
    if (next.has(entry.id)) next.delete(entry.id);
    else next.add(entry.id);
    onStateChange({ selectMode: true, selectedIds: next });
  };

  const card = el('article', {
    class: `vault-card stagger-item ${accentCls} ${isPinned ? 'is-pinned' : ''} ${isSelected ? 'is-selected' : ''} ${isSelecting ? 'is-selectable' : ''}`.trim(),
    'data-entry-id': entry.id,
  });

  if (isSelecting) {
    card.addEventListener('click', (e) => {
      // Allow clicking Eye reveal / Copy buttons or checkbox directly without double-toggling
      if (e.target.closest('button, input, a')) return;
      e.preventDefault();
      e.stopPropagation();
      toggleThisSelection();
    });
  } else {
    let longPressTimer = null;
    card.addEventListener('pointerdown', (e) => {
      if (e.target.closest('button, input, a')) return;
      longPressTimer = setTimeout(() => {
        triggerHaptic(24);
        toggleThisSelection();
      }, 500);
    });
    const cancelLongPress = () => {
      if (longPressTimer) {
        clearTimeout(longPressTimer);
        longPressTimer = null;
      }
    };
    card.addEventListener('pointerup', cancelLongPress);
    card.addEventListener('pointercancel', cancelLongPress);
    card.addEventListener('pointermove', cancelLongPress);
  }

  const selectCheckbox = isSelecting
    ? el('input', {
        type: 'checkbox',
        class: 'entry-select-cb',
        checked: isSelected,
        'aria-label': d.title || 'Select',
        onChange: () => toggleThisSelection(),
      })
    : null;

  const favBtn = el(
    'button',
    {
      type: 'button',
      class: `vault-mini-action ${isPinned ? 'is-fav' : ''}`.trim(),
      'aria-label': `${t(lang, 'favorites')} ${d.title}`,
      title: isPinned ? t(lang, 'pinnedBadge') : t(lang, 'pinAction'),
      onClick: async () => {
        triggerHaptic(10);
        await session.saveRecord({
          id: entry.id,
          type: 'password',
          data: { ...d, favorite: !d.favorite },
          createdAt: entry.createdAt,
        });
        await onRefresh();
      },
    },
    svgIcon('star', 13, isPinned),
    el('span', null, isPinned ? t(lang, 'pinnedBadge') : t(lang, 'pinAction'))
  );

  const moveIconBtn = el(
    'button',
    {
      type: 'button',
      class: 'vault-mini-action',
      'aria-label': `${t(lang, 'moveToSection')} ${d.title}`,
      title: t(lang, 'moveToSection'),
      onClick: () => {
        openMoveEntrySheet({ session, lang, entry, sections: sortedSections, onRefresh });
      },
    },
    svgIcon('link', 13),
    el('span', null, t(lang, 'moveShort'))
  );

  const editIconBtn = el(
    'button',
    {
      type: 'button',
      class: 'vault-mini-action vault-mini-edit',
      'aria-label': `${t(lang, 'edit')} ${d.title}`,
      title: t(lang, 'edit'),
      onClick: () =>
        openPasswordEditorSheet({
          session,
          lang,
          sections: sortedSections,
          entry,
          onSaved: onRefresh,
        }),
    },
    svgIcon('edit', 13),
    el('span', null, t(lang, 'edit'))
  );

  const deleteIconBtn = el(
    'button',
    {
      type: 'button',
      class: 'vault-mini-action vault-mini-delete',
      'data-testid': 'card-delete-btn',
      'aria-label': `${t(lang, 'delete')} ${d.title}`,
      title: t(lang, 'delete'),
      onClick: async () => {
        triggerHaptic(14);
        await session.trashRecord(entry.id);
        showToast(`${t(lang, 'movedToTrashToast')}: ${d.title || ''}`, 'info');
        await onRefresh();
      },
    },
    svgIcon('trash', 13),
    el('span', null, t(lang, 'delete'))
  );

  // Card Top Header (Title Pill + Quick Inline Actions including Outside Delete!)
  const titlePill = el(
    'div',
    { class: 'vault-card-title-pill' },
    el('span', { class: 'vault-card-emoji' }, sec?.data?.emoji || '🔐'),
    el('span', { class: 'vault-card-title-text' }, d.title || 'Untitled')
  );

  const topRow = el(
    'div',
    { class: 'vault-card-head' },
    selectCheckbox,
    titlePill,
    !state.showTrash && !isSelecting
      ? el('div', { class: 'vault-card-actions' }, favBtn, moveIconBtn, editIconBtn, deleteIconBtn)
      : null
  );
  card.appendChild(topRow);

  // Practical Per-Section Duplicate Reason Badges (visible when Duplicates filter is active)
  if (!state.showTrash && state.duplicatesOnly && dupInfo && dupInfo.reasons?.length > 0) {
    const dupRow = el(
      'div',
      { class: 'vault-dup-tags' },
      ...dupInfo.reasons.map((r) => {
        const label =
          r.type === 'username'
            ? t(lang, 'dupReasonUser')
            : r.type === 'password'
              ? t(lang, 'dupReasonPass')
              : t(lang, 'dupReasonTitle');
        return el('span', { class: 'vault-dup-tag' }, `⚠ ${label} (×${r.count})`);
      })
    );
    card.appendChild(dupRow);
  }

  // Trash actions if in trash view
  if (state.showTrash) {
    card.appendChild(
      el(
        'div',
        { class: 'entry-copy-row' },
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-primary',
            onClick: async () => {
              await session.restoreRecord(entry.id);
              await onRefresh();
            },
          },
          t(lang, 'restore')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-danger',
            onClick: async () => {
              await session.permanentlyDeleteRecord(entry.id);
              await onRefresh();
            },
          },
          t(lang, 'deleteForever')
        )
      )
    );
    return card;
  }

  // Clean Glass Field Rows inside Card — ALWAYS visible (including during Multi-Select & Bulk Move!)
  const rowsWrap = el('div', { class: 'vault-card-rows' });

  // Row 1: Username / Bill Number (or Notes preview if no username)
  const primaryVal = d.username || (!d.password && d.notes ? d.notes : '');
  if (primaryVal) {
    rowsWrap.appendChild(
      el(
        'div',
        { class: 'vault-field-pill' },
        el('span', { class: 'vault-field-icon vault-field-icon-user', 'aria-hidden': 'true' }, '👤'),
        el('span', { class: 'vault-field-val ltr-value' }, primaryVal),
        el(
          'button',
          {
            type: 'button',
            class: 'vault-pill-btn',
            'aria-label': `${t(lang, 'copyUser')} ${d.title}`,
            title: t(lang, 'copyUser'),
            onClick: () => copyField(primaryVal, t(lang, 'usernameLabel')),
          },
          svgIcon('copy', 15)
        )
      )
    );
  }

  // Row 2: Password (ONLY when present — optional for Bills!) with OUTSIDE Eye reveal toggle + Copy
  if (d.password) {
    const maskedText = '••••••••••';
    let isRevealed = false;
    let autoHideTimer = null;
    const pwdSpan = el('span', { class: 'vault-field-val ltr-value' }, maskedText);

    const hidePwd = () => {
      if (autoHideTimer) {
        clearTimeout(autoHideTimer);
        autoHideTimer = null;
      }
      isRevealed = false;
      pwdSpan.textContent = maskedText;
      eyeBtn.classList.remove('is-revealed');
    };

    const eyeBtn = el(
      'button',
      {
        type: 'button',
        class: 'vault-pill-btn',
        'aria-label': `${t(lang, 'revealToggle')} ${d.title}`,
        title: t(lang, 'revealToggle'),
        onClick: () => {
          triggerHaptic(8);
          if (isRevealed) {
            hidePwd();
          } else {
            isRevealed = true;
            pwdSpan.textContent = d.password;
            eyeBtn.classList.add('is-revealed');
            if (autoHideTimer) clearTimeout(autoHideTimer);
            autoHideTimer = setTimeout(hidePwd, 15000);
          }
        },
      },
      svgIcon('eye', 15)
    );

    rowsWrap.appendChild(
      el(
        'div',
        { class: 'vault-field-pill' },
        el('span', { class: 'vault-field-icon vault-field-icon-key', 'aria-hidden': 'true' }, '🔑'),
        pwdSpan,
        el(
          'div',
          { class: 'vault-pill-btns' },
          eyeBtn,
          el(
            'button',
            {
              type: 'button',
              class: 'vault-pill-btn',
              'aria-label': `${t(lang, 'copyPass')} ${d.title}`,
              title: t(lang, 'copyPass'),
              onClick: () => copyField(d.password, t(lang, 'passwordLabel')),
            },
            svgIcon('copy', 15)
          )
        )
      )
    );
  }

  if (rowsWrap.childNodes.length > 0) {
    card.appendChild(rowsWrap);
  }

  return card;
}

/**
 * Bottom sheet to quickly move an entry to another section (with inline Create-and-Move)
 */
function openMoveEntrySheet({ session, lang, entry, sections, onRefresh }) {
  const currentSecId = entry?.data?.sectionId;
  const list = el('div', { class: 'settings-group' });

  const moveTo = async (targetSectionId) => {
    await session.saveRecord({
      id: entry.id,
      type: 'password',
      createdAt: entry.createdAt,
      data: {
        ...entry.data,
        sectionId: targetSectionId,
      },
    });
    sheet.close();
    triggerHaptic();
    showToast(`${t(lang, 'save')} ✓`, 'success');
    await onRefresh();
  };

  for (const s of sections) {
    const isCurrent = s.id === currentSecId;
    const accentCls = accentClassForHex(s.data?.color);
    list.appendChild(
      el(
        'button',
        {
          type: 'button',
          class: `btn btn-block ${accentCls} ${isCurrent ? 'is-active' : ''}`.trim(),
          disabled: isCurrent,
          onClick: () => moveTo(s.id),
        },
        el('span', null, s.data?.emoji || '📁'),
        el('span', null, s.data?.name || ''),
        isCurrent ? el('span', { class: 'count-badge' }, '✓') : null
      )
    );
  }

  const newSecIn = el('input', {
    type: 'text',
    class: 'input',
    placeholder: t(lang, 'createAndMovePlaceholder'),
    autocomplete: 'off',
  });
  const quickCreateForm = el(
    'form',
    {
      class: 'glass-card glass-card-compact settings-group',
      onSubmit: async (e) => {
        e.preventDefault();
        const name = newSecIn.value.trim();
        if (!name) return;
        const nextTheme = pickNextUnusedSectionTheme(sections, SECTION_EMOJIS);
        const created = await session.saveRecord({
          type: 'section',
          data: {
            name,
            emoji: nextTheme.emoji,
            color: nextTheme.hex,
            order: sections.length,
          },
        });
        await moveTo(created.id);
      },
    },
    newSecIn,
    el('button', { type: 'submit', class: 'btn btn-sm btn-primary btn-block' }, svgIcon('plus', 15), t(lang, 'createAndMoveBtn'))
  );
  list.appendChild(quickCreateForm);

  const sheet = openBottomSheet({
    title: t(lang, 'moveToSection'),
    content: list,
  });
}

/**
 * Bottom sheet to move multiple selected entries to another section in bulk
 */
function openBulkMoveSheet({ session, lang, selectedIds, sections, onStateChange, onRefresh }) {
  const list = el('div', { class: 'settings-group' });

  const moveAllTo = async (targetSectionId) => {
    await session.movePasswordsToSection(selectedIds, targetSectionId);
    sheet.close();
    triggerHaptic();
    onStateChange({ selectMode: false, selectedIds: new Set() });
    showToast(`${t(lang, 'save')} ✓`, 'success');
    await onRefresh();
  };

  for (const s of sections) {
    const accentCls = accentClassForHex(s.data?.color);
    list.appendChild(
      el(
        'button',
        {
          type: 'button',
          class: `btn btn-block ${accentCls}`.trim(),
          onClick: () => moveAllTo(s.id),
        },
        el('span', null, s.data?.emoji || '📁'),
        el('span', null, s.data?.name || '')
      )
    );
  }

  const newSecIn = el('input', {
    type: 'text',
    class: 'input',
    placeholder: t(lang, 'createAndMovePlaceholder'),
    autocomplete: 'off',
  });
  const quickCreateForm = el(
    'form',
    {
      class: 'glass-card glass-card-compact settings-group',
      onSubmit: async (e) => {
        e.preventDefault();
        const name = newSecIn.value.trim();
        if (!name) return;
        const nextTheme = pickNextUnusedSectionTheme(sections, SECTION_EMOJIS);
        const created = await session.saveRecord({
          type: 'section',
          data: {
            name,
            emoji: nextTheme.emoji,
            color: nextTheme.hex,
            order: sections.length,
          },
        });
        await moveAllTo(created.id);
      },
    },
    newSecIn,
    el('button', { type: 'submit', class: 'btn btn-sm btn-primary btn-block' }, svgIcon('plus', 15), t(lang, 'createAndMoveBtn'))
  );
  list.appendChild(quickCreateForm);

  const sheet = openBottomSheet({
    title: `${t(lang, 'moveToSection')} (${selectedIds.size})`,
    content: list,
  });
}

/**
 * Bottom sheet to add or edit an account / bill entry.
 * - Password is 100% OPTIONAL (for Bills, Lines, Phone Numbers, etc.)
 * - URL field completely removed for clean simplicity!
 */
export function openPasswordEditorSheet({ session, lang, sections, entry = null, defaultSectionId = null, onSaved }) {
  const d = entry?.data || {};
  const titleInput = el('input', {
    id: 'pe-title',
    type: 'text',
    class: 'input',
    value: d.title || '',
    required: true,
    autocomplete: 'off',
  });
  const secSelect = el(
    'select',
    { id: 'pe-section', class: 'select' },
    ...sections.map((s) =>
      el(
        'option',
        { value: s.id, selected: (d.sectionId || defaultSectionId || sections[0]?.id) === s.id },
        `${s.data?.emoji || '📁'} ${s.data?.name || ''}`
      )
    )
  );
  const userInput = el('input', {
    id: 'pe-user',
    type: 'text',
    class: 'input ltr-value',
    value: d.username || '',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const pwdInput = el('input', {
    id: 'pe-pwd',
    type: 'password',
    class: 'input ltr-value',
    value: d.password || '',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: lang === 'en' ? 'Optional (leave empty for bills)' : 'اختياري (اتركه فارغاً للفواتير)',
  });
  const notesInput = el('textarea', {
    id: 'pe-notes',
    class: 'textarea',
    autocomplete: 'off',
    spellcheck: 'false',
  }, d.notes || '');
  const favCheck = el('input', { type: 'checkbox', checked: Boolean(d.favorite) });

  const meterLabel = el('span', { class: 'strength-caption' }, '');
  const updateMeter = () => {
    const st = evaluatePasswordStrength(pwdInput.value);
    meterLabel.textContent = pwdInput.value ? `${lang === 'en' ? st.labelEn : st.labelAr} (${st.entropyBits} bits)` : '';
  };
  pwdInput.addEventListener('input', updateMeter);
  updateMeter();

  const toggleVisBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-icon',
      'aria-label': t(lang, 'revealToggle'),
      onClick: () => {
        pwdInput.type = pwdInput.type === 'password' ? 'text' : 'password';
      },
    },
    svgIcon('eye', 18)
  );

  const genBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-sm',
      onClick: () =>
        openGeneratorSheet({
          session,
          lang,
          onSelect: (val) => {
            pwdInput.value = val;
            pwdInput.type = 'text';
            updateMeter();
          },
        }),
    },
    svgIcon('key', 15),
    t(lang, 'generateBtn')
  );

  const historyList = Array.isArray(d.passwordHistory) && d.passwordHistory.length > 0
    ? el(
        'details',
        { class: 'glass-card glass-card-compact' },
        el('summary', null, `${t(lang, 'passwordHistory')} (${d.passwordHistory.length})`),
        el(
          'div',
          { class: 'entry-fields' },
          ...d.passwordHistory.map((h) =>
            el(
              'div',
              { class: 'secret-field-row' },
              el('span', { class: 'ltr-value mono' }, h.value),
              el('span', { class: 'secret-field-label' }, new Date(h.changedAt).toLocaleDateString(lang === 'en' ? 'en' : 'ar'))
            )
          )
        )
      )
    : null;

  const form = el(
    'form',
    {
      onSubmit: async (e) => {
        e.preventDefault();
        const title = titleInput.value.trim();
        if (!title) return;

        const nextHistory = Array.isArray(d.passwordHistory) ? [...d.passwordHistory] : [];
        let passwordUpdatedAt = d.passwordUpdatedAt || new Date().toISOString();
        if (entry && d.password && d.password !== pwdInput.value) {
          nextHistory.unshift({ value: d.password, changedAt: new Date().toISOString() });
          passwordUpdatedAt = new Date().toISOString();
        }

        await session.saveRecord({
          id: entry?.id || null,
          type: 'password',
          createdAt: entry?.createdAt,
          data: {
            title,
            sectionId: secSelect.value || null,
            username: userInput.value.trim(),
            password: pwdInput.value,
            url: '',
            notes: notesInput.value,
            favorite: favCheck.checked,
            passwordUpdatedAt,
            passwordHistory: nextHistory.slice(0, 10),
          },
        });
        sheet.close();
        showToast(t(lang, 'save'), 'success');
        onSaved && (await onSaved());
      },
    },
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-title' }, t(lang, 'titleLabel')), titleInput),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-section' }, t(lang, 'sectionLabel')), secSelect),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-user' }, t(lang, 'usernameOrBillLabel')), userInput),
    el(
      'div',
      { class: 'field' },
      el('label', { class: 'field-label', for: 'pe-pwd' }, el('span', null, t(lang, 'passwordOptionalLabel')), genBtn),
      el('div', { class: 'input-row' }, pwdInput, toggleVisBtn),
      meterLabel
    ),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-notes' }, t(lang, 'notesLabel')), notesInput),
    el('label', { class: 'checkbox-row' }, favCheck, el('span', null, `✦ ${t(lang, 'favorites')}`)),
    historyList,
    el(
      'div',
      { class: 'form-grid-2' },
      el('button', { type: 'button', class: 'btn', onClick: () => sheet.close() }, t(lang, 'cancel')),
      el('button', { type: 'submit', class: 'btn btn-primary' }, t(lang, 'save'))
    ),
    entry
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-danger btn-block',
            onClick: async () => {
              await session.trashRecord(entry.id);
              sheet.close();
              showToast(t(lang, 'moveToTrash'), 'info');
              onSaved && (await onSaved());
            },
          },
          svgIcon('trash', 15),
          t(lang, 'delete')
        )
      : null
  );

  const sheet = openBottomSheet({
    title: entry ? t(lang, 'editEntry') : t(lang, 'addEntry'),
    content: form,
  });
}

/**
 * Bottom sheet to create, rename, change theme/icon, reorder (↑↓), and safely delete sections.
 */
function openManageSectionsSheet({ session, lang, sections, passwords, onRefresh }) {
  let currentSections = [...sections];
  const host = el('div', { class: 'settings-group' });

  const reloadLocal = async () => {
    const fresh = await session.listRecords('section');
    currentSections = fresh.sort((a, b) => (a.data?.order ?? 0) - (b.data?.order ?? 0));
    await onRefresh();
    renderList();
  };

  const renderList = () => {
    while (host.firstChild) host.removeChild(host.firstChild);

    const nextTheme = pickNextUnusedSectionTheme(currentSections, SECTION_EMOJIS);
    const nameIn = el('input', {
      type: 'text',
      class: 'input',
      placeholder: t(lang, 'sectionNamePlaceholder'),
      required: true,
      autocomplete: 'off',
    });
    const emojiSel = el(
      'select',
      { class: 'select', 'aria-label': 'Emoji' },
      ...SECTION_EMOJIS.map((em) => el('option', { value: em, selected: em === nextTheme.emoji }, em))
    );
    const colorSel = el(
      'select',
      { class: 'select', 'aria-label': 'Color' },
      ...SECTION_COLOR_OPTIONS.map((c) =>
        el('option', { value: c.hex, selected: c.hex === nextTheme.hex }, lang === 'en' ? c.nameEn : c.nameAr)
      )
    );

    const addForm = el(
      'form',
      {
        class: 'glass-card glass-card-compact settings-group',
        onSubmit: async (e) => {
          e.preventDefault();
          const name = nameIn.value.trim();
          if (!name) return;
          await session.saveRecord({
            type: 'section',
            data: { name, emoji: emojiSel.value, color: colorSel.value, order: currentSections.length },
          });
          showToast(`${t(lang, 'addSection')} ✓`, 'success');
          await reloadLocal();
        },
      },
      nameIn,
      el('div', { class: 'form-grid-2' }, emojiSel, colorSel),
      el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, svgIcon('plus', 16), t(lang, 'addSection'))
    );
    host.appendChild(addForm);

    currentSections.forEach((sec, idx) => {
      const d = sec.data || {};
      const itemCount = passwords.filter((p) => p.data?.sectionId === sec.id).length;

      const renameIn = el('input', { type: 'text', class: 'input', value: d.name || '', 'aria-label': d.name || 'Section' });
      const editEmojiSel = el(
        'select',
        { class: 'select', 'aria-label': 'Emoji' },
        ...SECTION_EMOJIS.map((em) => el('option', { value: em, selected: (d.emoji || '📁') === em }, em))
      );
      const editColorSel = el(
        'select',
        { class: 'select', 'aria-label': 'Color' },
        ...SECTION_COLOR_OPTIONS.map((c) =>
          el('option', { value: c.hex, selected: String(d.color || '#38bdf8').toLowerCase() === c.hex }, lang === 'en' ? c.nameEn : c.nameAr)
        )
      );
      const saveBtn = el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm btn-primary',
          onClick: async () => {
            if (!renameIn.value.trim()) return;
            await session.saveRecord({
              id: sec.id,
              type: 'section',
              createdAt: sec.createdAt,
              data: {
                ...d,
                name: renameIn.value.trim(),
                emoji: editEmojiSel.value,
                color: editColorSel.value,
              },
            });
            showToast(`${t(lang, 'save')} ✓`, 'success');
            await reloadLocal();
          },
        },
        t(lang, 'save')
      );

      const moveUpBtn = el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm',
          disabled: idx === 0,
          'aria-label': 'Move up',
          onClick: async () => {
            const prev = currentSections[idx - 1];
            await session.saveRecord({ id: sec.id, type: 'section', createdAt: sec.createdAt, data: { ...d, order: idx - 1 } });
            await session.saveRecord({ id: prev.id, type: 'section', createdAt: prev.createdAt, data: { ...prev.data, order: idx } });
            await reloadLocal();
          },
        },
        '↑'
      );

      const moveDownBtn = el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm',
          disabled: idx === currentSections.length - 1,
          'aria-label': 'Move down',
          onClick: async () => {
            const next = currentSections[idx + 1];
            await session.saveRecord({ id: sec.id, type: 'section', createdAt: sec.createdAt, data: { ...d, order: idx + 1 } });
            await session.saveRecord({ id: next.id, type: 'section', createdAt: next.createdAt, data: { ...next.data, order: idx } });
            await reloadLocal();
          },
        },
        '↓'
      );

      const delBtn = el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm btn-danger',
          'aria-label': `${t(lang, 'delete')} ${d.name || ''}`,
          onClick: () => {
            sheet.close();
            openDeleteSectionSheet({ session, lang, section: sec, allSections: currentSections, passwords, onRefresh });
          },
        },
        svgIcon('trash', 14),
        t(lang, 'delete')
      );

      host.appendChild(
        el(
          'div',
          { class: `glass-card glass-card-compact settings-group ${accentClassForHex(d.color)}` },
          el('div', { class: 'input-row' }, renameIn, saveBtn),
          el('div', { class: 'form-grid-2' }, editEmojiSel, editColorSel),
          el(
            'div',
            { class: 'toolbar-row' },
            el('span', { class: 'settings-row-desc' }, `${itemCount} ${t(lang, 'navPasswords')}`),
            moveUpBtn,
            moveDownBtn,
            delBtn
          )
        )
      );
    });
  };

  renderList();
  const sheet = openBottomSheet({ title: t(lang, 'manageSectionsBtn'), content: host });
}

function openDeleteSectionSheet({ session, lang, section, allSections, passwords, onRefresh }) {
  const others = allSections.filter((s) => s.id !== section.id);
  const affected = passwords.filter((p) => p.data?.sectionId === section.id);
  const targetSel = el(
    'select',
    { class: 'select' },
    ...others.map((s) => el('option', { value: s.id }, `${s.data?.emoji || '📁'} ${s.data?.name || ''}`))
  );

  const runDelete = async (mode) => {
    const now = new Date().toISOString();
    const updatedItems = affected.map((p) => ({
      id: p.id,
      type: 'password',
      createdAt: p.createdAt,
      deletedAt: mode === 'trash' ? now : null,
      data: {
        ...p.data,
        sectionId: mode === 'move' ? targetSel.value : p.data.sectionId,
      },
    }));
    const encryptedBatch = await session.encryptBatchForAtomicWrite(updatedItems);
    await session.storage.atomicOperationWithSnapshot({
      reason: `delete-section-${mode}`,
      putRecords: encryptedBatch,
      deleteIds: [section.id],
    });
    sheet.close();
    showToast(t(lang, 'delete'), 'info');
    await onRefresh();
  };

  const content = el(
    'div',
    { class: 'settings-group' },
    el('p', null, `${section.data?.emoji || '📁'} ${section.data?.name} (${affected.length})`),
    others.length > 0 ? el('div', { class: 'field' }, targetSel) : null,
    others.length > 0
      ? el('button', { type: 'button', class: 'btn btn-primary btn-block', onClick: () => runDelete('move') }, t(lang, 'secDeleteMove'))
      : null,
    el('button', { type: 'button', class: 'btn btn-danger btn-block', onClick: () => runDelete('trash') }, t(lang, 'secDeleteTrash'))
  );

  const sheet = openBottomSheet({ title: t(lang, 'secDeleteTitle'), content });
}
