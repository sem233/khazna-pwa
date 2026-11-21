/**
 * Khazna (خزنة) — Device-to-Device Encrypted Sync Bottom Sheet
 *
 * - Send Tab: generates an encrypted Sync Code (`KHAZNA-SYNC-1:...`) AND a clickable
 *   One-Tap Sync Link (`.../#sync=...`) using ONLY the URL hash fragment (never sent to server).
 *   Supports Delta (changes since last sync — super compact for links) or Full vault.
 * - Receive Tab: automatically pre-fills when opened from a `#sync=...` link (or accepts
 *   pasted codes/links), decrypts locally, previews exact diff (+new / updated / unchanged),
 *   and merges safely with an automatic encrypted rollback snapshot.
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

  // --- SEND TAB ---
  const renderSend = () => {
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const outWrap = el('div', { class: 'settings-group hidden' });

    const lastSyncAt = session.settings?.lastSyncAt || null;
    const scopeSel = el(
      'select',
      { class: 'select', 'aria-label': t(lang, 'syncScopeLabel') },
      el('option', { value: 'delta', selected: Boolean(lastSyncAt) }, t(lang, 'syncScopeDelta')),
      el('option', { value: 'full', selected: !lastSyncAt }, t(lang, 'syncScopeFull'))
    );

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
            return;
          }

          createBtn.disabled = true;
          try {
            const encoded = await encodeSyncPackage({
              payload,
              passphrase: passIn.value,
            });
            const isWebHost =
              (window.location.protocol === 'https:' || window.location.protocol === 'http:') &&
              window.location.origin !== 'null' &&
              !(window.Capacitor?.isNativePlatform?.());
            const baseUrl = isWebHost ? `${window.location.origin}${window.location.pathname}` : '';
            const linkInfo = isWebHost ? buildSyncLink(baseUrl, encoded.token) : { fitsUrl: false, url: '' };

            // Mark lastSyncAt on sender so subsequent delta syncs only carry new updates
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

            if (isWebHost && linkInfo.fitsUrl) {
              const linkArea = el('textarea', {
                class: 'textarea ltr-value mono',
                readonly: true,
                rows: 3,
                value: linkInfo.url,
                'data-testid': 'sync-output-link',
              });

              const shareOrCopyRow = el(
                'div',
                { class: 'form-grid-2' },
                el(
                  'button',
                  {
                    type: 'button',
                    class: 'btn btn-primary',
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
                  svgIcon('link', 16),
                  t(lang, 'syncCopyLinkBtn')
                ),
                typeof navigator.share === 'function'
                  ? el(
                      'button',
                      {
                        type: 'button',
                        class: 'btn',
                        onClick: async () => {
                          try {
                            await navigator.share({
                              title: t(lang, 'appName'),
                              text: t(lang, 'syncShareText'),
                              url: linkInfo.url,
                            });
                          } catch {
                            // user cancelled share sheet
                          }
                        },
                      },
                      svgIcon('share', 16),
                      t(lang, 'syncShareLinkBtn')
                    )
                  : el(
                      'button',
                      {
                        type: 'button',
                        class: 'btn',
                        'data-testid': 'sync-copy-code',
                        onClick: async () => {
                          try {
                            await session.clipboard.copySecret(encoded.code, 0);
                            triggerHaptic();
                            showToast(t(lang, 'syncCodeCopied'), 'success');
                          } catch {
                            showToast(t(lang, 'syncCopyManual'), 'warn');
                          }
                        },
                      },
                      svgIcon('copy', 16),
                      t(lang, 'syncCopyCodeBtn')
                    )
              );

              outWrap.appendChild(
                el(
                  'div',
                  { class: 'field' },
                  el('label', { class: 'field-label' }, t(lang, 'syncOneTapLinkLabel')),
                  linkArea
                )
              );
              outWrap.appendChild(shareOrCopyRow);
            } else if (isWebHost) {
              outWrap.appendChild(
                el('div', { class: 'banner banner-warn' }, el('span', null, t(lang, 'syncTooLargeForLink')))
              );
            }

            // Always also provide the raw KHAZNA-SYNC-1:... code for manual copy/paste
            const codeArea = el('textarea', {
              class: 'textarea ltr-value mono',
              readonly: true,
              rows: 2,
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
                    class: 'btn btn-sm',
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
                  svgIcon('copy', 15),
                  t(lang, 'syncCopyCodeBtn')
                )
              )
            );
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove('hidden');
          } finally {
            createBtn.disabled = false;
          }
        },
      },
      svgIcon('link', 17),
      t(lang, 'syncGenerateBtn')
    );

    body.appendChild(
      el('div', { class: 'banner banner-info' }, el('span', null, t(lang, 'syncSecurityNote')))
    );
    body.appendChild(errBox);
    body.appendChild(
      el(
        'div',
        { class: 'field' },
        el('label', { class: 'field-label' }, t(lang, 'syncScopeLabel')),
        scopeSel
      )
    );
    body.appendChild(
      el(
        'div',
        { class: 'field' },
        el('div', { class: 'field-label' }, el('span', null, t(lang, 'syncPassLabel')), genPassBtn),
        el('div', { class: 'input-row' }, passIn, toggleEye)
      )
    );
    body.appendChild(createBtn);
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

    const passIn = el('input', {
      type: 'password',
      class: 'input ltr-value',
      autocomplete: 'off',
      spellcheck: 'false',
      placeholder: t(lang, 'syncPassPlaceholder'),
      'data-testid': 'sync-recv-pass',
    });

    const stratSel = el(
      'select',
      { class: 'select', 'aria-label': t(lang, 'syncStrategyLabel') },
      el('option', { value: 'smart', selected: true }, t(lang, 'syncStrategySmart')),
      el('option', { value: 'add-only' }, t(lang, 'syncStrategyAddOnly'))
    );

    const previewBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-primary btn-block',
        'data-testid': 'sync-preview-btn',
        onClick: async () => {
          errBox.classList.add('hidden');
          clearNode(previewWrap);
          previewWrap.classList.add('hidden');
          previewBtn.disabled = true;

          try {
            const incoming = await decodeSyncPackage({
              input: codeIn.value,
              passphrase: passIn.value,
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
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove('hidden');
          } finally {
            previewBtn.disabled = false;
          }
        },
      },
      svgIcon('refresh', 17),
      t(lang, 'syncPreviewBtn')
    );

    if (initialSyncCode) {
      body.appendChild(
        el('div', { class: 'banner banner-success' }, el('span', null, t(lang, 'syncAutofilledBanner')))
      );
    }

    body.appendChild(errBox);
    body.appendChild(
      el(
        'div',
        { class: 'field' },
        el('label', { class: 'field-label' }, t(lang, 'syncReceiveCodeLabel')),
        codeIn
      )
    );
    body.appendChild(
      el(
        'div',
        { class: 'field' },
        el('label', { class: 'field-label' }, t(lang, 'syncPassLabel')),
        passIn
      )
    );
    body.appendChild(
      el(
        'div',
        { class: 'field' },
        el('label', { class: 'field-label' }, t(lang, 'syncStrategyLabel')),
        stratSel
      )
    );
    body.appendChild(previewBtn);
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
