/**
 * Khazna 100% Local Import & Export Guided Bottom Sheet
 *
 * Import:
 * - File picker OR direct paste (plus Web Share Target handoff)
 * - Auto-detects .vault, .spass, Bitwarden JSON, Khazna JSON, Generic JSON, and 8+ CSV dialects
 * - Preview counts, duplicates, warnings, and manual Universal CSV Column Mapper UI
 * - Target section OR automatic folder-to-section mapping + duplicate strategy (skip/replace/keep-both)
 * - Atomic transaction with automatic encrypted snapshot & instant Undo button
 *
 * Export:
 * - Encrypted .vault (recommended full-fidelity), Plain JSON, Chrome CSV, Bitwarden JSON, best-effort .spass
 * - Plain exports require Re-authentication + Red Warning + explicit confirmation
 * - Scope filter (All or specific section)
 * - Delivery via Download, Web Share API (WhatsApp/Drive), or Copy as Text
 */

import { CSV_TARGET_FIELDS } from '../import-export/csv.js';
import {
  exportBestEffortSpass,
  exportBitwardenJson,
  exportChromeCsv,
  exportEncryptedVault,
  exportPlainJson,
  parseImportSource,
} from '../import-export/formats.js';
import { buildImportPreview, commitImportTransaction } from '../import-export/manager.js';
import { formatError, t } from '../i18n/strings.js';
import { el, openBottomSheet, requestReauth, showToast, svgIcon, triggerHaptic } from './dom.js';

export function openImportExportSheet({
  session,
  lang,
  sections,
  passwords,
  cards,
  notes,
  initialTab = 'import',
  initialPastedText = '',
  onChanged,
}) {
  let activeTab = initialTab;
  const bodyHost = el('div', { class: 'settings-group' });

  const tabImp = el('button', { type: 'button', class: `seg-btn ${activeTab === 'import' ? 'is-active' : ''}` }, t(lang, 'tabImport'));
  const tabExp = el('button', { type: 'button', class: `seg-btn ${activeTab === 'export' ? 'is-active' : ''}` }, t(lang, 'tabExport'));

  const renderTab = () => {
    while (bodyHost.firstChild) bodyHost.removeChild(bodyHost.firstChild);
    tabImp.classList.toggle('is-active', activeTab === 'import');
    tabExp.classList.toggle('is-active', activeTab === 'export');

    if (activeTab === 'import') {
      renderImportTab();
    } else {
      renderExportTab();
    }
  };

  // --- IMPORT TAB ---
  const renderImportTab = () => {
    let selectedFileName = '';
    let parsedBundle = null;
    let customCsvMapping = null;
    let lastSnapshotId = null;

    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const textIn = el('textarea', {
      id: 'imp-text',
      class: 'textarea ltr-value',
      autocomplete: 'off',
      spellcheck: 'false',
      placeholder: 'name,url,username,password,note...',
    }, initialPastedText || '');
    const pwdIn = el('input', {
      id: 'imp-pwd',
      type: 'password',
      class: 'input ltr-value',
      autocomplete: 'off',
      spellcheck: 'false',
      placeholder: t(lang, 'importPwdLabel'),
    });
    const fileLabel = el('span', { class: 'settings-row-desc' }, '');
    const fileInput = el('input', {
      type: 'file',
      class: 'sr-only',
      accept: '.vault,.spass,.json,.csv,.txt',
      onChange: async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        selectedFileName = file.name;
        fileLabel.textContent = file.name;
        textIn.value = await file.text();
      },
    });

    const previewHost = el('div', { class: 'settings-group' });

    const runAnalyze = async () => {
      errBox.classList.add('hidden');
      while (previewHost.firstChild) previewHost.removeChild(previewHost.firstChild);

      try {
        parsedBundle = await parseImportSource({
          rawText: textIn.value,
          fileName: selectedFileName,
          password: pwdIn.value,
          customCsvMapping,
        });
        const preview = buildImportPreview(parsedBundle, { sections, passwords, cards, notes });

        previewHost.appendChild(
          el(
            'div',
            { class: 'banner banner-info' },
            el(
              'span',
              null,
              `${preview.format} — 🔑 ${preview.counts.passwords} • 💳 ${preview.counts.cards} • 📝 ${preview.counts.notes} (${t(lang, 'duplicates')}: ${preview.duplicates.total})`
            )
          )
        );

        if (preview.format === 'spass') {
          previewHost.appendChild(el('div', { class: 'banner banner-warn' }, el('span', null, t(lang, 'spassHonestNote'))));
        }

        // Manual CSV Column Mapper UI
        if (parsedBundle.isCsv && preview.csvHeaders) {
          const mapperBox = el('details', { class: 'glass-card glass-card-compact' }, el('summary', null, lang === 'en' ? 'CSV Column Mapping (Manual Override)' : 'تعيين أعمدة CSV (تعديل يدوي)'));
          const mapGrid = el('div', { class: 'settings-group' });
          const nextMap = { ...preview.csvColumnMap };

          preview.csvHeaders.forEach((hdr, idx) => {
            const sel = el(
              'select',
              {
                class: 'select',
                'aria-label': hdr,
                onChange: (e) => {
                  nextMap[idx] = e.target.value;
                  customCsvMapping = nextMap;
                  runAnalyze();
                },
              },
              ...CSV_TARGET_FIELDS.map((f) => el('option', { value: f, selected: nextMap[idx] === f }, f))
            );
            mapGrid.appendChild(el('div', { class: 'input-row' }, el('span', { class: 'ltr-inline mono' }, hdr), sel));
          });
          mapperBox.appendChild(mapGrid);
          previewHost.appendChild(mapperBox);
        }

        const sectionModeSel = el(
          'select',
          { class: 'select', 'aria-label': 'Section mapping mode' },
          el('option', { value: 'map-folders' }, lang === 'en' ? 'Map source folders to sections' : 'تحويل مجلدات المصدر إلى أقسام تلقائياً'),
          el('option', { value: 'single-section' }, lang === 'en' ? 'Import all into one section' : 'استيراد الكل داخل قسم محدد')
        );
        const targetSecSel = el(
          'select',
          { class: 'select', 'aria-label': t(lang, 'sectionLabel') },
          ...sections.map((s) => el('option', { value: s.id }, `${s.data?.emoji || '📁'} ${s.data?.name || ''}`))
        );
        const dupSel = el(
          'select',
          { class: 'select', 'aria-label': 'Duplicate strategy' },
          el('option', { value: 'skip' }, lang === 'en' ? 'Duplicates: Skip' : 'المكرر: تخطّي'),
          el('option', { value: 'replace' }, lang === 'en' ? 'Duplicates: Replace existing' : 'المكرر: استبدال الحالي'),
          el('option', { value: 'keep-both' }, lang === 'en' ? 'Duplicates: Keep both' : 'المكرر: الاحتفاظ بالاثنين')
        );

        const commitBtn = el(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary btn-block',
            onClick: async () => {
              commitBtn.disabled = true;
              try {
                const report = await commitImportTransaction({
                  session,
                  bundle: parsedBundle,
                  sectionMode: sectionModeSel.value,
                  targetSectionId: targetSecSel.value || null,
                  duplicateStrategy: dupSel.value,
                });
                lastSnapshotId = report.snapshotId;
                // Wipe plaintext & import password from UI immediately
                textIn.value = '';
                pwdIn.value = '';
                parsedBundle = null;

                while (previewHost.firstChild) previewHost.removeChild(previewHost.firstChild);
                previewHost.appendChild(
                  el(
                    'div',
                    { class: 'banner banner-success' },
                    el(
                      'span',
                      null,
                      lang === 'en'
                        ? `Imported: +${report.added.passwords} passwords, +${report.added.cards} cards, +${report.added.notes} notes (skipped: ${report.skipped.passwords + report.skipped.cards + report.skipped.notes}).`
                        : `تم الاستيراد: +${report.added.passwords} كلمة مرور، +${report.added.cards} بطاقة، +${report.added.notes} ملاحظة (تم تخطي: ${report.skipped.passwords + report.skipped.cards + report.skipped.notes}).`
                    )
                  )
                );
                previewHost.appendChild(el('div', { class: 'banner banner-warn' }, el('span', null, t(lang, 'deletePlaintextReminder'))));
                previewHost.appendChild(
                  el(
                    'button',
                    {
                      type: 'button',
                      class: 'btn btn-danger btn-block',
                      onClick: async () => {
                        if (!lastSnapshotId) return;
                        await session.storage.restoreSnapshot(lastSnapshotId);
                        showToast(t(lang, 'undoImportBtn'), 'info');
                        onChanged && (await onChanged());
                        sheet.close();
                      },
                    },
                    t(lang, 'undoImportBtn')
                  )
                );
                onChanged && (await onChanged());
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove('hidden');
                commitBtn.disabled = false;
              }
            },
          },
          svgIcon('upload', 18),
          t(lang, 'commitImportBtn')
        );

        previewHost.appendChild(el('div', { class: 'form-grid-2' }, sectionModeSel, targetSecSel));
        previewHost.appendChild(dupSel);
        previewHost.appendChild(commitBtn);
      } catch (err) {
        errBox.textContent = formatError(err, lang);
        errBox.classList.remove('hidden');
      }
    };

    bodyHost.appendChild(errBox);
    bodyHost.appendChild(
      el(
        'div',
        { class: 'input-row' },
        fileInput,
        el('button', { type: 'button', class: 'btn', onClick: () => fileInput.click() }, svgIcon('upload', 16), t(lang, 'pickFileBtn')),
        fileLabel
      )
    );
    bodyHost.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'imp-text' }, t(lang, 'pasteTextLabel')), textIn));
    bodyHost.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'imp-pwd' }, t(lang, 'importPwdLabel')), pwdIn));
    bodyHost.appendChild(el('button', { type: 'button', class: 'btn btn-primary btn-block', onClick: runAnalyze }, t(lang, 'analyzeImportBtn')));
    bodyHost.appendChild(previewHost);
  };

  // --- EXPORT TAB ---
  const renderExportTab = () => {
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const fmtSel = el(
      'select',
      { id: 'exp-fmt', class: 'select' },
      el('option', { value: 'vault' }, lang === 'en' ? 'Encrypted Backup (.vault) — Recommended' : 'نسخة مشفّرة (.vault) — الموصى به'),
      el('option', { value: 'plain-json' }, lang === 'en' ? 'Plain JSON (Unencrypted)' : 'JSON نصي (غير مشفّر)'),
      el('option', { value: 'chrome-csv' }, lang === 'en' ? 'Chrome-Compatible CSV (Unencrypted)' : 'CSV متوافق مع كروم (غير مشفّر)'),
      el('option', { value: 'bitwarden-json' }, lang === 'en' ? 'Bitwarden JSON (Unencrypted)' : 'Bitwarden JSON (غير مشفّر)'),
      el('option', { value: 'spass' }, lang === 'en' ? 'Samsung Pass (.spass — Best Effort)' : 'Samsung Pass (.spass — أفضل جهد)')
    );
    const scopeSel = el(
      'select',
      { id: 'exp-scope', class: 'select' },
      el('option', { value: 'all' }, lang === 'en' ? 'Entire Vault' : 'كامل الخزنة'),
      ...sections.map((s) => el('option', { value: s.id }, `${s.data?.emoji || '📁'} ${s.data?.name || ''}`))
    );
    const expPwdIn = el('input', {
      id: 'exp-pwd',
      type: 'password',
      class: 'input ltr-value',
      autocomplete: 'off',
      spellcheck: 'false',
      placeholder: lang === 'en' ? 'Backup password (min 8 chars)' : 'كلمة مرور النسخة الاحتياطية (٨ أحرف+)',
    });
    const plainWarnBox = el('div', { class: 'banner banner-danger hidden' }, el('span', null, t(lang, 'plainExportWarn')));
    const confirmPlainCheck = el('input', { type: 'checkbox' });
    const confirmPlainRow = el(
      'label',
      { class: 'checkbox-row hidden' },
      confirmPlainCheck,
      el('span', null, lang === 'en' ? 'I understand this export is unencrypted.' : 'أفهم أن هذا التصدير غير مشفّر وسأحذفه فوراً بعد الاستخدام.')
    );

    const syncFormatUi = () => {
      const f = fmtSel.value;
      const isPlain = f === 'plain-json' || f === 'chrome-csv' || f === 'bitwarden-json';
      plainWarnBox.classList.toggle('hidden', !isPlain);
      confirmPlainRow.classList.toggle('hidden', !isPlain);
      expPwdIn.parentElement.classList.toggle('hidden', isPlain);
    };
    fmtSel.addEventListener('change', syncFormatUi);

    const buildExportBlob = async () => {
      errBox.classList.add('hidden');
      const f = fmtSel.value;
      const isPlain = f === 'plain-json' || f === 'chrome-csv' || f === 'bitwarden-json';

      if (isPlain && !confirmPlainCheck.checked) {
        throw new Error(lang === 'en' ? 'Please confirm the unencrypted export warning.' : 'يرجى تأكيد فهم تحذير التصدير غير المشفّر.');
      }

      // Re-authentication required for exports
      const ok = await requestReauth({ session, lang });
      if (!ok) return null;

      const scope = scopeSel.value;
      const scopedPasswords = scope === 'all' ? passwords : passwords.filter((p) => p.data?.sectionId === scope);
      const scopedSections = scope === 'all' ? sections : sections.filter((s) => s.id === scope);
      const scopedCards = scope === 'all' ? cards : [];
      const scopedNotes = scope === 'all' ? notes : [];

      const stamp = new Date().toISOString().slice(0, 10);
      let text;
      let fileName;
      let mime = 'application/json';

      if (f === 'vault') {
        const kdfSpec = { kdf: session.header.kdf, params: session.header.kdfParams };
        text = await exportEncryptedVault(
          { sections: scopedSections, passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes },
          expPwdIn.value,
          kdfSpec,
          { enforceMinimums: false }
        );
        fileName = `khazna-backup-${stamp}.vault`;
      } else if (f === 'spass') {
        text = await exportBestEffortSpass(
          { passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes },
          expPwdIn.value
        );
        fileName = `khazna-${stamp}.spass`;
        mime = 'text/plain';
      } else if (f === 'chrome-csv') {
        text = exportChromeCsv(scopedPasswords);
        fileName = `khazna-chrome-${stamp}.csv`;
        mime = 'text/csv';
      } else if (f === 'bitwarden-json') {
        text = exportBitwardenJson({ sections: scopedSections, passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes });
        fileName = `khazna-bitwarden-${stamp}.json`;
      } else {
        text = exportPlainJson({ sections: scopedSections, passwords: scopedPasswords, cards: scopedCards, notes: scopedNotes });
        fileName = `khazna-plain-${stamp}.json`;
      }

      expPwdIn.value = '';
      await session.updateSettings({ lastBackupAt: new Date().toISOString() });
      return { text, fileName, mime };
    };

    const triggerDownload = async () => {
      try {
        const res = await buildExportBlob();
        if (!res) return;
        const blob = new Blob([res.text], { type: res.mime });
        const url = URL.createObjectURL(blob);
        const a = el('a', { href: url, download: res.fileName });
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        triggerHaptic();
        showToast(`${res.fileName}`, 'success');
      } catch (err) {
        errBox.textContent = formatError(err, lang);
        errBox.classList.remove('hidden');
      }
    };

    const triggerShare = async () => {
      try {
        const res = await buildExportBlob();
        if (!res) return;
        const file = new File([res.text], res.fileName, { type: res.mime });
        if (navigator.share && (!navigator.canShare || navigator.canShare({ files: [file] }))) {
          await navigator.share({ title: 'Khazna Backup', files: [file] });
        } else {
          showToast(lang === 'en' ? 'Web Share is unavailable on this browser — use Download.' : 'المشاركة غير مدعومة في هذا المتصفح — استخدم التنزيل.', 'warn');
        }
      } catch (err) {
        if (err?.name !== 'AbortError') {
          errBox.textContent = formatError(err, lang);
          errBox.classList.remove('hidden');
        }
      }
    };

    const triggerCopy = async () => {
      try {
        const res = await buildExportBlob();
        if (!res) return;
        await session.clipboard.copySecret(res.text, session.settings?.clipboardClearSec ?? 30);
        triggerHaptic();
        showToast(t(lang, 'copiedToast'), 'success');
      } catch (err) {
        errBox.textContent = formatError(err, lang);
        errBox.classList.remove('hidden');
      }
    };

    bodyHost.appendChild(errBox);
    bodyHost.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'exp-fmt' }, lang === 'en' ? 'Format' : 'صيغة التصدير'), fmtSel));
    bodyHost.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'exp-scope' }, lang === 'en' ? 'Scope' : 'نطاق التصدير'), scopeSel));
    bodyHost.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'exp-pwd' }, lang === 'en' ? 'Backup Password' : 'كلمة مرور النسخة'), expPwdIn));
    bodyHost.appendChild(plainWarnBox);
    bodyHost.appendChild(confirmPlainRow);
    bodyHost.appendChild(
      el(
        'div',
        { class: 'settings-group' },
        el('button', { type: 'button', class: 'btn btn-primary btn-block', onClick: triggerDownload }, svgIcon('download', 18), lang === 'en' ? 'Download File' : 'تنزيل الملف'),
        el(
          'div',
          { class: 'form-grid-2' },
          el('button', { type: 'button', class: 'btn', onClick: triggerShare }, lang === 'en' ? 'Share (Drive / WhatsApp)' : 'مشاركة (Drive / واتساب)'),
          el('button', { type: 'button', class: 'btn', onClick: triggerCopy }, svgIcon('copy', 16), lang === 'en' ? 'Copy Text' : 'نسخ كنص')
        )
      )
    );
    syncFormatUi();
  };

  tabImp.addEventListener('click', () => { activeTab = 'import'; renderTab(); });
  tabExp.addEventListener('click', () => { activeTab = 'export'; renderTab(); });

  renderTab();

  const content = el(
    'div',
    { class: 'settings-group' },
    el('div', { class: 'segmented' }, tabImp, tabExp),
    bodyHost
  );

  const sheet = openBottomSheet({ title: t(lang, 'importTitle'), content });
  return sheet;
}
