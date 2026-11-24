/**
 * Khazna (خزنة) — Device-to-Device Encrypted Sync & Transfer Bottom Sheet
 *
 * - Supports encrypting/decrypting sync codes with the SAME Pattern or Master Password as your vault
 *   so old & new devices share the exact same lock and sync seamlessly via code.
 * - Zero external servers — 100% local PBKDF2-SHA-256 + AES-256-GCM + gzip.
 */

import { generatePassword } from '../crypto/vault-crypto.js';
import { formatError, t } from '../i18n/strings.js';
import {
  applySyncMerge,
  buildSyncLink,
  decodeSyncPackage,
  encodeSyncPackage,
  planSyncMerge,
  selectSyncRecords,
} from '../import-export/sync.js';
import { clearNode, el, openBottomSheet, showToast, svgIcon, triggerHaptic } from './dom.js';
import { createPatternPad } from './pattern-pad.js';

export function openSyncSheet({
  session,
  lang,
  sections,
  passwords,
  cards,
  notes,
  initialTab = 'send',
  initialSyncCode = '',
  onSynced,
}) {
  let activeTab = initialSyncCode ? 'receive' : initialTab;

  const root = el('div', { class: 'settings-group' });
  const body = el('div', { class: 'settings-group' });

  const tabSend = el(
    'button',
    {
      type: 'button',
      class: `seg-btn ${activeTab === 'send' ? 'is-active' : ''}`.trim(),
      onClick: () => {
        activeTab = 'send';
        renderBody();
      },
    },
    t(lang, 'syncTabSend')
  );

  const tabRecv = el(
    'button',
    {
      type: 'button',
      class: `seg-btn ${activeTab === 'receive' ? 'is-active' : ''}`.trim(),
      onClick: () => {
        activeTab = 'receive';
        renderBody();
      },
    },
    t(lang, 'syncTabReceive')
  );

  root.append(el('div', { class: 'segmented' }, tabSend, tabRecv), body);

  // --- SEND / TRANSFER TAB ---
  const renderSend = () => {
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const outWrap = el('div', { class: 'settings-group hidden' });

    const lastSyncAt = session.settings?.lastSyncAt || null;
    const scopeSel = el(
      'select',
      { class: 'select', 'aria-label': t(lang, 'syncScopeLabel') },
      el('option', { value: 'full', selected: true }, t(lang, 'syncScopeFull')),
      el('option', { value: 'delta', selected: false }, t(lang, 'syncScopeDelta'))
    );

    let keyMode = session.hasPatternUnlock ? 'pattern' : 'password';
    const keyHost = el('div', { class: 'settings-group' });
    const segPat = el('button', { type: 'button', class: `seg-btn ${keyMode === 'pattern' ? 'is-active' : ''}`.trim() }, t(lang, 'patternTabLabel'));
    const segPwd = el('button', { type: 'button', class: `seg-btn ${keyMode === 'password' ? 'is-active' : ''}`.trim() }, t(lang, 'passwordTabLabel'));

    const runGenerate = async (secret, onDone) => {
      errBox.classList.add('hidden');
      const scope = scopeSel.value;
      const payload = selectSyncRecords({
        sections,
        passwords,
        cards,
        notes,
        mode: scope,
        sinceIso: scope === 'delta' ? lastSyncAt : null,
      });

      const totalItems =
        payload.passwords.length + payload.cards.length + payload.notes.length;
      if (totalItems === 0 && payload.sections.length === 0) {
        errBox.textContent = t(lang, 'syncNothingToSend');
        errBox.classList.remove('hidden');
        if (onDone) onDone(false);
        return;
      }

      try {
        const encoded = await encodeSyncPackage({
          payload,
          passphrase: secret,
        });
        const isWebHost =
          (window.location.protocol === 'https:' || window.location.protocol === 'http:') &&
          window.location.origin !== 'null' &&
          !(window.Capacitor?.isNativePlatform?.());
        const baseUrl = isWebHost ? `${window.location.origin}${window.location.pathname}` : '';
        const linkInfo = isWebHost ? buildSyncLink(baseUrl, encoded.token) : { fitsUrl: false, url: '' };

        await session.updateSettings({ lastSyncAt: new Date().toISOString() });

        clearNode(outWrap);
        outWrap.classList.remove('hidden');

        const kb = (encoded.byteLength / 1024).toFixed(1);
        outWrap.appendChild(
          el(
            'div',
            { class: 'banner banner-success' },
            el(
              'span',
              null,
              `${t(lang, 'syncReadySummary')}: ${encoded.counts.passwords} 🔑 • ${encoded.counts.cards} 💳 • ${encoded.counts.notes} 📝 (${kb} KB)`
            )
          )
        );

        // Primary Sync Code (works everywhere: PC file://, Android APK, Chrome Extension)
        const codeArea = el('textarea', {
          class: 'textarea ltr-value mono',
          readonly: true,
          rows: 3,
          value: encoded.code,
          'data-testid': 'sync-output-code',
        });
        outWrap.appendChild(
          el(
            'div',
            { class: 'field' },
            el('label', { class: 'field-label' }, t(lang, 'syncCodeLabel')),
            codeArea,
            el(
              'button',
              {
                type: 'button',
                class: 'btn btn-primary btn-block',
                'data-testid': 'sync-copy-code',
                onClick: async () => {
                  try {
                    await session.clipboard.copySecret(encoded.code, 0);
                    triggerHaptic();
                    showToast(t(lang, 'syncCodeCopied'), 'success');
                  } catch {
                    codeArea.select();
                    showToast(t(lang, 'syncCopyManual'), 'warn');
                  }
                },
              },
              svgIcon('copy', 16),
              t(lang, 'syncCopyCodeBtn')
            )
          )
        );

        if (isWebHost && linkInfo.fitsUrl) {
          const linkArea = el('textarea', {
            class: 'textarea ltr-value mono',
            readonly: true,
            rows: 2,
            value: linkInfo.url,
            'data-testid': 'sync-output-link',
          });
          outWrap.appendChild(
            el(
              'div',
              { class: 'field' },
              el('label', { class: 'field-label' }, t(lang, 'syncOneTapLinkLabel')),
              linkArea,
              el(
                'button',
                {
                  type: 'button',
                  class: 'btn btn-sm',
                  'data-testid': 'sync-copy-link',
                  onClick: async () => {
                    try {
                      await session.clipboard.copySecret(linkInfo.url, 0);
                      triggerHaptic();
                      showToast(t(lang, 'syncLinkCopied'), 'success');
                    } catch {
                      linkArea.select();
                      showToast(t(lang, 'syncCopyManual'), 'warn');
                    }
                  },
                },
                svgIcon('link', 15),
                t(lang, 'syncCopyLinkBtn')
              )
            )
          );
        }

        if (onDone) onDone(true);
      } catch (err) {
        errBox.textContent = formatError(err, lang);
        errBox.classList.remove('hidden');
        if (onDone) onDone(false);
      }
    };

    const renderKeyInput = () => {
      clearNode(keyHost);
      segPat.classList.toggle('is-active', keyMode === 'pattern');
      segPwd.classList.toggle('is-active', keyMode === 'password');

      if (keyMode === 'pattern') {
        const pad = createPatternPad({
          lang,
          hint: lang === 'en' ? 'Draw your vault pattern to encrypt the transfer code' : 'ارسم نمط خزنتك لإنشاء كود النقل المشفّر فوراً',
          onComplete: async (secret) => {
            pad.setDisabled(true);
            pad.setSuccess(lang === 'en' ? 'Encrypting...' : 'جارٍ التشفير...');
            await runGenerate(secret, (ok) => {
              pad.setDisabled(false);
              if (ok) pad.setSuccess(t(lang, 'syncReadySummary'));
              else pad.reset();
            });
          },
        });
        keyHost.appendChild(pad.wrap);
      } else {
        const passIn = el('input', {
          type: 'password',
          class: 'input ltr-value',
          autocomplete: 'off',
          spellcheck: 'false',
          placeholder: t(lang, 'syncPassPlaceholder'),
          'data-testid': 'sync-send-pass',
        });
        const toggleEye = el(
          'button',
          {
            type: 'button',
            class: 'btn btn-icon',
            'aria-label': t(lang, 'holdToReveal'),
            onClick: () => {
              passIn.type = passIn.type === 'password' ? 'text' : 'password';
            },
          },
          svgIcon('eye', 18)
        );
        const genPassBtn = el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm',
            onClick: () => {
              passIn.value = generatePassword({ length: 14, lower: true, upper: true, digits: true, symbols: false, excludeLookalikes: true });
              passIn.type = 'text';
              triggerHaptic();
            },
          },
          svgIcon('key', 15),
          t(lang, 'syncGenPassBtn')
        );
        const createBtn = el(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary btn-block',
            'data-testid': 'sync-generate-btn',
            onClick: async () => {
              createBtn.disabled = true;
              await runGenerate(passIn.value, () => {
                createBtn.disabled = false;
              });
            },
          },
          svgIcon('link', 17),
          t(lang, 'syncGenerateBtn')
        );
        keyHost.appendChild(
          el(
            'div',
            { class: 'field' },
            el('div', { class: 'field-label' }, el('span', null, t(lang, 'syncPassLabel')), genPassBtn),
            el('div', { class: 'input-row' }, passIn, toggleEye)
          )
        );
        keyHost.appendChild(createBtn);
      }
    };

    segPat.addEventListener('click', () => { keyMode = 'pattern'; renderKeyInput(); });
    segPwd.addEventListener('click', () => { keyMode = 'password'; renderKeyInput(); });
    renderKeyInput();

    body.appendChild(el('div', { class: 'banner banner-info' }, el('span', null, t(lang, 'syncLockMethodHint'))));
    body.appendChild(errBox);
    body.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'syncScopeLabel')), scopeSel));
    body.appendChild(el('div', { class: 'segmented' }, segPat, segPwd));
    body.appendChild(keyHost);
    body.appendChild(outWrap);
  };

  // --- RECEIVE TAB ---
  const renderReceive = () => {
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const previewWrap = el('div', { class: 'settings-group hidden' });

    const codeIn = el('textarea', {
      class: 'textarea ltr-value mono',
      rows: 3,
      autocomplete: 'off',
      spellcheck: 'false',
      value: initialSyncCode || '',
      placeholder: t(lang, 'syncReceivePlaceholder'),
      'data-testid': 'sync-recv-input',
    });

    const stratSel = el(
      'select',
      { class: 'select', 'aria-label': t(lang, 'syncStrategyLabel') },
      el('option', { value: 'smart', selected: true }, t(lang, 'syncStrategySmart')),
      el('option', { value: 'add-only' }, t(lang, 'syncStrategyAddOnly'))
    );

    let keyMode = session.hasPatternUnlock ? 'pattern' : 'password';
    const keyHost = el('div', { class: 'settings-group' });
    const segPat = el('button', { type: 'button', class: `seg-btn ${keyMode === 'pattern' ? 'is-active' : ''}`.trim() }, t(lang, 'patternTabLabel'));
    const segPwd = el('button', { type: 'button', class: `seg-btn ${keyMode === 'password' ? 'is-active' : ''}`.trim() }, t(lang, 'passwordTabLabel'));

    const runPreview = async (secret, onDone) => {
      errBox.classList.add('hidden');
      clearNode(previewWrap);
      previewWrap.classList.add('hidden');

      try {
        const incoming = await decodeSyncPackage({
          input: codeIn.value,
          passphrase: secret,
        });

        const plan = planSyncMerge({
          incoming,
          localSections: sections,
          localPasswords: passwords,
          localCards: cards,
          localNotes: notes,
          strategy: stratSel.value,
        });

        previewWrap.classList.remove('hidden');
        const s = plan.summary;
        previewWrap.appendChild(
          el(
            'div',
            { class: 'banner banner-info', 'data-testid': 'sync-diff-summary' },
            el(
              'span',
              null,
              `${t(lang, 'syncPreviewDiff')}: +${s.added} ${t(lang, 'syncAddedLabel')} • ${s.updated} ${t(lang, 'syncUpdatedLabel')} • ${s.unchanged} ${t(lang, 'syncUnchangedLabel')}`
            )
          )
        );

        const applyBtn = el(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary btn-block',
            'data-testid': 'sync-apply-btn',
            onClick: async () => {
              applyBtn.disabled = true;
              try {
                const res = await applySyncMerge({ session, plan });
                triggerHaptic();
                showToast(
                  `${t(lang, 'syncSuccessToast')} (+${res.summary.added} / ↻${res.summary.updated})`,
                  'success',
                  4000
                );
                sheet.close();
                if (onSynced) await onSynced();
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove('hidden');
                applyBtn.disabled = false;
              }
            },
          },
          svgIcon('check', 17),
          t(lang, 'syncApplyBtn')
        );
        previewWrap.appendChild(applyBtn);
        if (onDone) onDone(true);
      } catch (err) {
        errBox.textContent = formatError(err, lang);
        errBox.classList.remove('hidden');
        if (onDone) onDone(false, formatError(err, lang));
      }
    };

    const renderRecvKey = () => {
      clearNode(keyHost);
      segPat.classList.toggle('is-active', keyMode === 'pattern');
      segPwd.classList.toggle('is-active', keyMode === 'password');

      if (keyMode === 'pattern') {
        const pad = createPatternPad({
          lang,
          hint: lang === 'en' ? 'Draw the SAME pattern used on the sender device' : 'ارسم نفس النمط لفك تشفير ومعاينة الكود',
          onComplete: async (secret) => {
            pad.setDisabled(true);
            pad.setSuccess(t(lang, 'unlocking'));
            await runPreview(secret, (ok, msg) => {
              pad.setDisabled(false);
              if (ok) pad.setSuccess(t(lang, 'syncPreviewDiff'));
              else pad.setError(msg);
            });
          },
        });
        keyHost.appendChild(pad.wrap);
      } else {
        const passIn = el('input', {
          type: 'password',
          class: 'input ltr-value',
          autocomplete: 'off',
          spellcheck: 'false',
          placeholder: t(lang, 'syncPassPlaceholder'),
          'data-testid': 'sync-recv-pass',
        });
        const previewBtn = el(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary btn-block',
            'data-testid': 'sync-preview-btn',
            onClick: async () => {
              previewBtn.disabled = true;
              await runPreview(passIn.value, () => {
                previewBtn.disabled = false;
              });
            },
          },
          svgIcon('refresh', 17),
          t(lang, 'syncPreviewBtn')
        );
        keyHost.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'syncPassLabel')), passIn));
        keyHost.appendChild(previewBtn);
      }
    };

    segPat.addEventListener('click', () => { keyMode = 'pattern'; renderRecvKey(); });
    segPwd.addEventListener('click', () => { keyMode = 'password'; renderRecvKey(); });
    renderRecvKey();

    if (initialSyncCode) {
      body.appendChild(
        el('div', { class: 'banner banner-success' }, el('span', null, t(lang, 'syncAutofilledBanner')))
      );
    }

    body.appendChild(errBox);
    body.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'syncReceiveCodeLabel')), codeIn));
    body.appendChild(el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'syncStrategyLabel')), stratSel));
    body.appendChild(el('div', { class: 'segmented' }, segPat, segPwd));
    body.appendChild(keyHost);
    body.appendChild(previewWrap);
  };

  const renderBody = () => {
    tabSend.classList.toggle('is-active', activeTab === 'send');
    tabRecv.classList.toggle('is-active', activeTab === 'receive');
    clearNode(body);
    if (activeTab === 'send') renderSend();
    else renderReceive();
  };

  renderBody();
  const sheet = openBottomSheet({ title: t(lang, 'syncTitle'), content: root });
  return sheet;
}
