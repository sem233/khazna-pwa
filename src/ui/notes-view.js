/**
 * Khazna Secure Notes View
 *
 * - Plain text + optional interactive checklist
 * - Pin to top, instant Arabic/English search, copy whole note
 * - Encrypted autosave of unsaved drafts inside IndexedDB ('draft' record type)
 */

import { matchesQuery } from '../domain/search.js';
import { formatError, t } from '../i18n/strings.js';
import { el, openBottomSheet, showToast, svgIcon, triggerHaptic } from './dom.js';

const DRAFT_RECORD_ID = 'draft_note_active';

export function renderNotesView({ session, lang, notes, query, onQueryChange, onRefresh }) {
  const container = el('div', { class: 'settings-group view-enter' });

  const searchIn = el('input', {
    type: 'search',
    class: 'input',
    value: query || '',
    placeholder: t(lang, 'searchPlaceholder'),
    autocomplete: 'off',
    onInput: (e) => onQueryChange(e.target.value),
  });

  container.appendChild(
    el('div', { class: 'search-wrap' }, el('span', { class: 'search-icon' }, svgIcon('search', 18)), searchIn)
  );

  const filtered = notes
    .filter((n) => {
      const d = n.data || {};
      const clText = (d.checklist || []).map((c) => c.text).join(' ');
      return matchesQuery(query, [d.title, d.body, clText]);
    })
    .sort((a, b) => {
      if (Boolean(a.data?.pinned) !== Boolean(b.data?.pinned)) return a.data?.pinned ? -1 : 1;
      return String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''));
    });

  if (filtered.length === 0) {
    container.appendChild(
      el(
        'div',
        { class: 'glass-card empty-state' },
        svgIcon('note', 38),
        el('h3', null, t(lang, 'emptyNotes')),
        el('p', null, t(lang, 'emptyNotesSub'))
      )
    );
    return container;
  }

  const grid = el('div', { class: 'notes-grid', 'data-testid': 'notes-grid' });

  for (const note of filtered) {
    const d = note.data || {};
    const checklist = Array.isArray(d.checklist) ? d.checklist : [];

    const copyFullNote = async () => {
      const lines = [d.title || ''];
      if (d.body) lines.push(d.body);
      if (checklist.length) {
        lines.push(...checklist.map((i) => `${i.done ? '[x]' : '[ ]'} ${i.text}`));
      }
      try {
        await session.clipboard.copySecret(lines.join('\n').trim(), session.settings?.clipboardClearSec ?? 30);
        triggerHaptic();
        showToast(t(lang, 'copiedToast'), 'success');
      } catch (err) {
        showToast(formatError(err, lang), 'error');
      }
    };

    const clNodes = checklist.slice(0, 4).map((item, idx) =>
      el(
        'label',
        { class: `checklist-item ${item.done ? 'is-done' : ''}`.trim() },
        el('input', {
          type: 'checkbox',
          checked: Boolean(item.done),
          onChange: async (e) => {
            const nextList = checklist.map((c, i) => (i === idx ? { ...c, done: e.target.checked } : c));
            await session.saveRecord({
              id: note.id,
              type: 'note',
              createdAt: note.createdAt,
              data: { ...d, checklist: nextList },
            });
            await onRefresh();
          },
        }),
        el('span', null, item.text)
      )
    );

    const card = el(
      'article',
      { class: 'glass-card note-card stagger-item' },
      el(
        'div',
        { class: 'entry-top' },
        el('h3', { class: 'entry-title' }, d.pinned ? '📌 ' : '', d.title || 'Untitled'),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-icon btn-ghost',
            'aria-label': `${t(lang, 'pinNote')} ${d.title}`,
            onClick: async () => {
              await session.saveRecord({
                id: note.id,
                type: 'note',
                createdAt: note.createdAt,
                data: { ...d, pinned: !d.pinned },
              });
              await onRefresh();
            },
          },
          svgIcon('pin', 17, Boolean(d.pinned))
        )
      ),
      d.body ? el('p', { class: 'note-body-preview' }, d.body) : null,
      clNodes.length ? el('div', { class: 'settings-group' }, ...clNodes) : null,
      el(
        'div',
        { class: 'entry-actions-row' },
        el('button', { type: 'button', class: 'btn btn-sm', onClick: copyFullNote }, svgIcon('copy', 14), t(lang, 'copyAll')),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm',
            'aria-label': `${t(lang, 'edit')} ${d.title}`,
            onClick: () => openNoteEditorSheet({ session, lang, note, onSaved: onRefresh }),
          },
          svgIcon('edit', 14),
          t(lang, 'edit')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-danger',
            'aria-label': `${t(lang, 'delete')} ${d.title}`,
            onClick: async () => {
              await session.trashRecord(note.id);
              await onRefresh();
            },
          },
          svgIcon('trash', 14)
        )
      )
    );

    grid.appendChild(card);
  }

  container.appendChild(grid);
  return container;
}

/**
 * Bottom sheet for creating/editing a secure note with encrypted draft autosave.
 */
export async function openNoteEditorSheet({ session, lang, note = null, onSaved }) {
  let initialData = note?.data || { title: '', body: '', checklist: [], pinned: false };

  // Restore encrypted autosaved draft when creating a new note
  if (!note) {
    try {
      const drafts = await session.listRecords('draft');
      const existingDraft = drafts.find((d) => d.id === DRAFT_RECORD_ID);
      if (existingDraft?.data && (existingDraft.data.title || existingDraft.data.body || existingDraft.data.checklist?.length)) {
        initialData = existingDraft.data;
      }
    } catch {
      // ignore missing draft
    }
  }

  const checklist = Array.isArray(initialData.checklist)
    ? initialData.checklist.map((c) => ({ ...c }))
    : [];

  const draftStatus = el('span', { class: 'settings-row-desc' }, '');
  let autosaveTimer = null;

  const scheduleAutosave = () => {
    if (note) return; // autosave applies to new unsaved drafts
    if (autosaveTimer) clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(async () => {
      try {
        await session.saveRecord({
          id: DRAFT_RECORD_ID,
          type: 'draft',
          data: {
            title: titleIn.value,
            body: bodyIn.value,
            checklist,
            pinned: pinCheck.checked,
          },
        });
        draftStatus.textContent = `✓ ${t(lang, 'draftSaved')}`;
      } catch {
        // ignore if locked mid-edit
      }
    }, 600);
  };

  const titleIn = el('input', {
    id: 'ne-title',
    type: 'text',
    class: 'input',
    value: initialData.title || '',
    required: true,
    autocomplete: 'off',
    onInput: scheduleAutosave,
  });
  const bodyIn = el('textarea', {
    id: 'ne-body',
    class: 'textarea',
    autocomplete: 'off',
    spellcheck: 'false',
    onInput: scheduleAutosave,
  }, initialData.body || '');
  const pinCheck = el('input', {
    type: 'checkbox',
    checked: Boolean(initialData.pinned),
    onChange: scheduleAutosave,
  });

  const clHost = el('div', { class: 'settings-group' });
  const renderChecklistEditor = () => {
    while (clHost.firstChild) clHost.removeChild(clHost.firstChild);
    checklist.forEach((item, idx) => {
      clHost.appendChild(
        el(
          'div',
          { class: 'input-row' },
          el('input', {
            type: 'checkbox',
            checked: Boolean(item.done),
            onChange: (e) => { item.done = e.target.checked; scheduleAutosave(); },
          }),
          el('input', {
            type: 'text',
            class: 'input',
            value: item.text,
            autocomplete: 'off',
            onInput: (e) => { item.text = e.target.value; scheduleAutosave(); },
          }),
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-icon btn-danger',
              'aria-label': 'Remove item',
              onClick: () => {
                checklist.splice(idx, 1);
                renderChecklistEditor();
                scheduleAutosave();
              },
            },
            svgIcon('close', 16)
          )
        )
      );
    });
  };
  renderChecklistEditor();

  const addItemBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-sm',
      onClick: () => {
        checklist.push({ text: '', done: false });
        renderChecklistEditor();
        scheduleAutosave();
      },
    },
    svgIcon('plus', 15),
    t(lang, 'addChecklistItem')
  );

  const form = el(
    'form',
    {
      onSubmit: async (e) => {
        e.preventDefault();
        if (autosaveTimer) clearTimeout(autosaveTimer);
        const title = titleIn.value.trim();
        if (!title) return;
        await session.saveRecord({
          id: note?.id || null,
          type: 'note',
          createdAt: note?.createdAt,
          data: {
            title,
            body: bodyIn.value,
            checklist: checklist.filter((c) => c.text.trim() !== ''),
            pinned: pinCheck.checked,
          },
        });
        if (!note) {
          await session.permanentlyDeleteRecord(DRAFT_RECORD_ID).catch(() => {});
        }
        sheet.close();
        showToast(t(lang, 'save'), 'success');
        onSaved && (await onSaved());
      },
    },
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ne-title' }, el('span', null, t(lang, 'noteTitleLabel')), draftStatus), titleIn),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ne-body' }, t(lang, 'noteBodyLabel')), bodyIn),
    el('div', { class: 'field' }, el('div', { class: 'field-label' }, el('span', null, t(lang, 'checklistLabel')), addItemBtn), clHost),
    el('label', { class: 'checkbox-row' }, pinCheck, el('span', null, t(lang, 'pinNote'))),
    el(
      'div',
      { class: 'form-grid-2' },
      el('button', { type: 'button', class: 'btn', onClick: () => sheet.close() }, t(lang, 'cancel')),
      el('button', { type: 'submit', class: 'btn btn-primary' }, t(lang, 'save'))
    )
  );

  const sheet = openBottomSheet({
    title: note ? t(lang, 'editNote') : t(lang, 'addNote'),
    content: form,
    onClose: () => {
      if (autosaveTimer) clearTimeout(autosaveTimer);
    },
  });
}
