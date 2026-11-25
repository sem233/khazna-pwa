/**
 * Khazna Passwords & Sections View
 *
 * Features:
 * - Sections: create, rename, delete (asks Move vs Trash items), reorder, emoji + accent color
 * - Entries: title, section, username, password, URL, notes, favorite, created/updated, password history (last 10)
 * - Copy button next to EVERY field + Copy Combo (Two-Step floating mini-bar OR One-Tap two lines)
 * - Masked passwords by default; press-and-hold reveal with 10s auto-hide
 * - Instant local Arabic/English diacritics-insensitive search, filters (favorites, duplicates, trash), sort
 * - Long-press / toggle multi-select bulk trash, 30-day trash restore
 */

import { evaluatePasswordStrength } from '../crypto/vault-crypto.js';
import { filterAndSortPasswords } from '../domain/search.js';
import { formatError, t } from '../i18n/strings.js';
import {
  accentClassForHex,
  attachHoldToReveal,
  el,
  openBottomSheet,
  SECTION_COLOR_OPTIONS,
  showToast,
  svgIcon,
  triggerHaptic,
} from './dom.js';
import { openGeneratorSheet } from './generator-sheet.js';

const SECTION_EMOJIS = ['🔐', '🏦', '💬', '💼', '🛒', '🎮', '☁️', '🏠', '📱', '✈️', '🏥', '🎓'];

export function renderPasswordsView({
  session,
  lang,
  sections,
  passwords,
  trashedPasswords,
  state,
  onStateChange,
  onRefresh,
  onShowTwoStepBar,
}) {
  const container = el('div', { class: 'settings-group view-enter' });

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

  // --- Search & Controls ---
  const searchInput = el('input', {
    type: 'search',
    class: 'input',
    value: state.query || '',
    placeholder: t(lang, 'searchPlaceholder'),
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': t(lang, 'searchPlaceholder'),
    onInput: (e) => {
      onStateChange({ query: e.target.value }, { keepFocus: true });
    },
  });

  const sortSelect = el(
    'select',
    {
      class: 'select',
      'aria-label': 'Sort',
      onChange: (e) => onStateChange({ sortBy: e.target.value }),
    },
    el('option', { value: 'updated-desc', selected: state.sortBy === 'updated-desc' }, t(lang, 'sortUpdated')),
    el('option', { value: 'title-asc', selected: state.sortBy === 'title-asc' }, t(lang, 'sortTitleAsc')),
    el('option', { value: 'created-desc', selected: state.sortBy === 'created-desc' }, t(lang, 'sortCreated')),
    el('option', { value: 'favorites-first', selected: state.sortBy === 'favorites-first' }, t(lang, 'sortFavorites'))
  );

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

  // --- Section Chips Strip ---
  const sectionById = new Map(sections.map((s) => [s.id, s]));
  const countBySec = new Map();
  for (const p of passwords) {
    const sid = p.data?.sectionId || 'uncategorized';
    countBySec.set(sid, (countBySec.get(sid) || 0) + 1);
  }

  const strip = el('div', { class: 'section-strip', role: 'tablist', 'aria-label': t(lang, 'manageSections') });

  const addChip = (label, count, active, cls, onClick) => {
    strip.appendChild(
      el(
        'button',
        {
          type: 'button',
          role: 'tab',
          'aria-selected': active ? 'true' : 'false',
          class: `sec-chip ${cls || ''} ${active ? 'is-active' : ''}`.trim(),
          onClick,
        },
        cls ? el('span', { class: 'sec-dot' }) : null,
        el('span', null, label),
        count !== null ? el('span', { class: 'count-badge' }, String(count)) : null
      )
    );
  };

  addChip(
    t(lang, 'allSections'),
    passwords.length,
    !state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && state.sectionId === 'all',
    '',
    () => onStateChange({ sectionId: 'all', showTrash: false, favoritesOnly: false, duplicatesOnly: false })
  );

  const sortedSections = [...sections].sort((a, b) => (a.data?.order ?? 0) - (b.data?.order ?? 0));
  for (const sec of sortedSections) {
    const d = sec.data || {};
    addChip(
      `${d.emoji || '📁'} ${d.name || ''}`,
      countBySec.get(sec.id) || 0,
      !state.showTrash && state.sectionId === sec.id,
      accentClassForHex(d.color),
      () => onStateChange({ sectionId: sec.id, showTrash: false, favoritesOnly: false, duplicatesOnly: false })
    );
  }

  const favCount = passwords.filter((p) => p.data?.favorite).length;
  addChip(`★ ${t(lang, 'favorites')}`, favCount, !state.showTrash && state.favoritesOnly, '', () =>
    onStateChange({ sectionId: 'all', showTrash: false, favoritesOnly: !state.favoritesOnly, duplicatesOnly: false })
  );
  addChip(t(lang, 'duplicates'), null, !state.showTrash && state.duplicatesOnly, '', () =>
    onStateChange({ sectionId: 'all', showTrash: false, favoritesOnly: false, duplicatesOnly: !state.duplicatesOnly })
  );
  addChip(`🗑 ${t(lang, 'trash')}`, trashedPasswords.length, Boolean(state.showTrash), '', () =>
    onStateChange({ showTrash: !state.showTrash, favoritesOnly: false, duplicatesOnly: false })
  );

  strip.appendChild(
    el(
      'button',
      {
        type: 'button',
        class: 'sec-chip',
        onClick: () => openManageSectionsSheet({ session, lang, sections: sortedSections, passwords, onRefresh }),
      },
      svgIcon('plus', 15),
      t(lang, 'manageSections')
    )
  );

  container.appendChild(strip);

  // --- Filtered List (computed before toolbar so Select All knows visible entries) ---
  const sourceList = state.showTrash ? trashedPasswords : passwords;
  const visibleEntries = filterAndSortPasswords(sourceList, {
    query: state.query,
    sectionId: state.showTrash ? 'all' : state.sectionId,
    favoritesOnly: !state.showTrash && state.favoritesOnly,
    duplicatesOnly: !state.showTrash && state.duplicatesOnly,
    sortBy: state.sortBy,
  });

  // --- Always-visible Sections Manager, Multi-Select & Sort Toolbar ---
  const selectedIds = state.selectedIds || new Set();
  const isSelecting = Boolean(state.selectMode) || selectedIds.size > 0;

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
  } else {
    container.appendChild(
      el(
        'div',
        { class: 'pw-controls-bar' },
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm',
            'data-testid': 'manage-sections-btn',
            onClick: () => openManageSectionsSheet({ session, lang, sections: sortedSections, passwords, onRefresh }),
          },
          svgIcon('plus', 15),
          t(lang, 'manageSectionsBtn')
        ),
        !state.showTrash && visibleEntries.length > 0
          ? el(
              'button',
              {
                type: 'button',
                class: 'btn btn-sm',
                'data-testid': 'multi-select-btn',
                onClick: () => onStateChange({ selectMode: true, selectedIds: new Set() }),
              },
              svgIcon('check', 15),
              t(lang, 'multiSelectBtn')
            )
          : null,
        sortSelect
      )
    );
  }

  // Hero banner when filtering by a single section
  if (!state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && state.sectionId !== 'all') {
    const activeSec = sectionById.get(state.sectionId);
    if (activeSec) {
      const ad = activeSec.data || {};
      const accentCls = accentClassForHex(ad.color);
      container.appendChild(
        el(
          'div',
          { class: `section-hero-banner ${accentCls}` },
          el(
            'div',
            { class: 'section-hero-info' },
            el('span', { class: 'section-hero-emoji' }, ad.emoji || '📁'),
            el(
              'div',
              { class: 'section-hero-text' },
              el('h2', null, ad.name || ''),
              el('p', null, `${visibleEntries.length} ${t(lang, 'navPasswords')}`)
            )
          ),
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm btn-primary',
              onClick: () => {
                openPasswordEditorSheet({
                  session,
                  lang,
                  sections: sortedSections,
                  defaultSectionId: activeSec.id,
                  onSaved: onRefresh,
                });
              },
            },
            svgIcon('plus', 14),
            t(lang, 'addEntry')
          )
        )
      );
    }
  }

  const listWrap = el('div', { class: 'entry-list', 'data-testid': 'password-list' });

  if (visibleEntries.length === 0) {
    listWrap.appendChild(
      el(
        'div',
        { class: 'glass-card empty-state' },
        svgIcon('lock', 36),
        el('h3', null, t(lang, 'emptyPasswords')),
        el('p', null, t(lang, 'emptyPasswordsSub'))
      )
    );
    container.appendChild(listWrap);
    return container;
  }

  // ---- Grouped by section view ----
  const isGrouped = state.sectionId === 'all' && !state.showTrash && !state.favoritesOnly && !state.duplicatesOnly && !state.query;

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

    // Sort groups in section order
    for (const sec of sortedSections) {
      const g = groups.get(sec.id);
      if (!g || g.entries.length === 0) continue;
      const sd = sec.data || {};
      const accentCls = accentClassForHex(sd.color);

      const toggleArrow = el('span', { class: 'count-badge' }, '▼');
      const groupBody = el('div', { class: 'section-group-body' });
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
            onStateChange,
            onRefresh,
            onShowTwoStepBar,
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
      const groupBody = el('div', { class: 'section-group-body' });
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
            onStateChange,
            onRefresh,
            onShowTwoStepBar,
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
    for (const entry of visibleEntries) {
      listWrap.appendChild(
        buildEntryCard({
          entry,
          sectionById,
          selectedIds,
          state,
          session,
          lang,
          sortedSections,
          copyField,
          onStateChange,
          onRefresh,
          onShowTwoStepBar,
        })
      );
    }
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
  onStateChange,
  onRefresh,
  onShowTwoStepBar,
}) {
  const d = entry.data || {};
  const sec = sectionById.get(d.sectionId);
  const accentCls = accentClassForHex(sec?.data?.color);
  const isSelected = selectedIds.has(entry.id);
  const isSelecting = (Boolean(state.selectMode) || selectedIds.size > 0) && !state.showTrash;

  const toggleThisSelection = () => {
    const next = new Set(selectedIds);
    if (next.has(entry.id)) next.delete(entry.id);
    else next.add(entry.id);
    onStateChange({ selectMode: true, selectedIds: next });
  };

  const card = el('article', {
    class: `entry-card stagger-item ${accentCls} ${isSelected ? 'is-selected' : ''} ${isSelecting ? 'is-selectable' : ''}`.trim(),
    'data-entry-id': entry.id,
  });

  if (isSelecting) {
    card.addEventListener('click', (e) => {
      if (e.target.closest('input[type="checkbox"]')) return;
      e.preventDefault();
      e.stopPropagation();
      toggleThisSelection();
    });
  } else {
    // Long-press multi-select support (mobile)
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
      class: `btn btn-icon-sm btn-ghost ${d.favorite ? 'is-fav' : ''}`.trim(),
      'aria-label': `${t(lang, 'favorites')} ${d.title}`,
      title: t(lang, 'favorites'),
      onClick: async () => {
        await session.saveRecord({
          id: entry.id,
          type: 'password',
          data: { ...d, favorite: !d.favorite },
          createdAt: entry.createdAt,
        });
        await onRefresh();
      },
    },
    svgIcon('star', 16, Boolean(d.favorite))
  );

  const moveIconBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-icon-sm btn-ghost',
      'aria-label': `${t(lang, 'moveToSection')} ${d.title}`,
      title: t(lang, 'moveToSection'),
      onClick: () => {
        openMoveEntrySheet({ session, lang, entry, sections: sortedSections, onRefresh });
      },
    },
    svgIcon('link', 15)
  );

  const editIconBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-icon-sm btn-ghost',
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
    svgIcon('edit', 15)
  );

  const topRow = el(
    'div',
    { class: 'entry-top entry-top-simple' },
    selectCheckbox,
    el(
      'div',
      { class: 'entry-title-group' },
      el(
        'h3',
        { class: 'entry-title' },
        el('span', null, sec?.data?.emoji || '🔐'),
        el('span', null, d.title || 'Untitled')
      ),
      d.username ? el('p', { class: 'entry-sub ltr-value' }, d.username) : null
    ),
    !state.showTrash && !isSelecting
      ? el('div', { class: 'entry-mini-icons' }, favBtn, moveIconBtn, editIconBtn)
      : null
  );

  const actionsRow = el('div', { class: 'entry-copy-row' });

  if (state.showTrash) {
    actionsRow.appendChild(
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
      )
    );
    actionsRow.appendChild(
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
    );
  } else {
    if (d.username) {
      actionsRow.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm entry-copy-btn',
            'aria-label': `${t(lang, 'copyUser')} ${d.title}`,
            onClick: () => copyField(d.username, t(lang, 'usernameLabel')),
          },
          svgIcon('copy', 14),
          t(lang, 'copyUser')
        )
      );
    }

    if (d.password) {
      actionsRow.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-dual-copy entry-copy-btn',
            'aria-label': `${t(lang, 'copyPass')} ${d.title}`,
            onClick: () => copyField(d.password, t(lang, 'passwordLabel')),
          },
          svgIcon('key', 14),
          t(lang, 'copyPass')
        )
      );
    }
  }

  card.classList.add('entry-card-simple');
  card.appendChild(topRow);
  if (!isSelecting && actionsRow.childNodes.length > 0) {
    card.appendChild(actionsRow);
  }
  return card;
}

/**
 * Bottom sheet to quickly move an entry to another section
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

  // Inline create new section & move directly into it
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
        const created = await session.saveRecord({
          type: 'section',
          data: {
            name,
            emoji: '📁',
            color: SECTION_COLOR_OPTIONS[sections.length % SECTION_COLOR_OPTIONS.length].hex,
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

  // Inline create new section & move all selected passwords into it
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
        const created = await session.saveRecord({
          type: 'section',
          data: {
            name,
            emoji: '📁',
            color: SECTION_COLOR_OPTIONS[sections.length % SECTION_COLOR_OPTIONS.length].hex,
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
 * Bottom sheet to add or edit a password entry (including password history last 10).
 */
export function openPasswordEditorSheet({ session, lang, sections, entry = null, defaultSectionId = null, onSaved }) {
  const d = entry?.data || {};
  const titleInput = el('input', { id: 'pe-title', type: 'text', class: 'input', value: d.title || '', required: true, autocomplete: 'off' });
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
  const userInput = el('input', { id: 'pe-user', type: 'text', class: 'input ltr-value', value: d.username || '', autocomplete: 'off', spellcheck: 'false' });
  const pwdInput = el('input', { id: 'pe-pwd', type: 'password', class: 'input ltr-value', value: d.password || '', autocomplete: 'off', spellcheck: 'false' });
  const urlInput = el('input', { id: 'pe-url', type: 'url', class: 'input ltr-value', value: d.url || '', placeholder: 'https://', autocomplete: 'off', spellcheck: 'false' });
  const notesInput = el('textarea', { id: 'pe-notes', class: 'textarea', autocomplete: 'off', spellcheck: 'false' }, d.notes || '');
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
      'aria-label': t(lang, 'holdToReveal'),
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
            url: urlInput.value.trim(),
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
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-user' }, t(lang, 'usernameLabel')), userInput),
    el(
      'div',
      { class: 'field' },
      el('label', { class: 'field-label', for: 'pe-pwd' }, el('span', null, t(lang, 'passwordLabel')), genBtn),
      el('div', { class: 'input-row' }, pwdInput, toggleVisBtn),
      meterLabel
    ),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-url' }, t(lang, 'urlLabel')), urlInput),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'pe-notes' }, t(lang, 'notesLabel')), notesInput),
    el('label', { class: 'checkbox-row' }, favCheck, el('span', null, t(lang, 'favorites'))),
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
 * Bottom sheet to create, rename, reorder, and safely delete sections (asks Move vs Trash items + atomic snapshot).
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

    // Add new section form
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
      ...SECTION_EMOJIS.map((em) => el('option', { value: em }, em))
    );
    const colorSel = el(
      'select',
      { class: 'select', 'aria-label': 'Color' },
      ...SECTION_COLOR_OPTIONS.map((c) => el('option', { value: c.hex }, lang === 'en' ? c.nameEn : c.nameAr))
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
