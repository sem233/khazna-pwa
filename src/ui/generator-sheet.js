/**
 * Khazna CSPRNG Password & Passphrase Generator Bottom Sheet
 */

import {
  evaluatePasswordStrength,
  generatePassphrase,
  generatePassword,
} from '../crypto/vault-crypto.js';
import { t } from '../i18n/strings.js';
import { el, openBottomSheet, showToast, svgIcon, triggerHaptic } from './dom.js';

export function openGeneratorSheet({ session, lang, onSelect = null }) {
  let mode = 'password'; // 'password' | 'passphrase'
  let length = 20;
  let wordCount = 6;
  let lower = true;
  let upper = true;
  let digits = true;
  let symbols = true;
  let excludeLookalikes = false;
  let currentValue = '';

  const previewNode = el('div', { class: 'recovery-key-display', 'data-testid': 'generated-password' });
  const meterWrap = el(
    'div',
    { class: 'strength-meter strength-4' },
    el(
      'div',
      { class: 'strength-bars' },
      el('div', { class: 'strength-bar' }),
      el('div', { class: 'strength-bar' }),
      el('div', { class: 'strength-bar' }),
      el('div', { class: 'strength-bar' })
    ),
    el('div', { class: 'strength-caption' })
  );

  const regen = () => {
    try {
      currentValue = mode === 'password'
        ? generatePassword({ length, lower, upper, digits, symbols, excludeLookalikes })
        : generatePassphrase({ wordCount, separator: '-', capitalize: true, includeNumber: true });
      previewNode.textContent = currentValue;
      const st = evaluatePasswordStrength(currentValue);
      meterWrap.className = `strength-meter strength-${st.score}`;
      const cap = meterWrap.querySelector('.strength-caption');
      cap.textContent = `${lang === 'en' ? st.labelEn : st.labelAr} (${st.entropyBits} bits)`;
    } catch {
      // keep previous if all charsets unchecked
    }
  };

  const optionsHost = el('div', { class: 'settings-group' });

  const renderOptions = () => {
    while (optionsHost.firstChild) optionsHost.removeChild(optionsHost.firstChild);

    if (mode === 'password') {
      const lenVal = el('span', { class: 'mono' }, String(length));
      const range = el('input', {
        type: 'range',
        min: 8,
        max: 64,
        value: length,
        onInput: (e) => {
          length = parseInt(e.target.value, 10);
          lenVal.textContent = String(length);
          regen();
        },
      });
      optionsHost.appendChild(
        el(
          'div',
          { class: 'field' },
          el('label', { class: 'field-label' }, el('span', null, t(lang, 'genLength')), lenVal),
          range
        )
      );

      const mkCheck = (label, checked, onChange) => {
        const cb = el('input', {
          type: 'checkbox',
          checked,
          onChange: (e) => {
            onChange(e.target.checked);
            if (!lower && !upper && !digits && !symbols) {
              lower = true;
              renderOptions();
            }
            regen();
          },
        });
        return el('label', { class: 'checkbox-row' }, cb, el('span', null, label));
      };

      optionsHost.appendChild(mkCheck(t(lang, 'genLower'), lower, (v) => { lower = v; }));
      optionsHost.appendChild(mkCheck(t(lang, 'genUpper'), upper, (v) => { upper = v; }));
      optionsHost.appendChild(mkCheck(t(lang, 'genDigits'), digits, (v) => { digits = v; }));
      optionsHost.appendChild(mkCheck(t(lang, 'genSymbols'), symbols, (v) => { symbols = v; }));
      optionsHost.appendChild(mkCheck(t(lang, 'genNoLookalikes'), excludeLookalikes, (v) => { excludeLookalikes = v; }));
    } else {
      const wcVal = el('span', { class: 'mono' }, String(wordCount));
      const range = el('input', {
        type: 'range',
        min: 4,
        max: 10,
        value: wordCount,
        onInput: (e) => {
          wordCount = parseInt(e.target.value, 10);
          wcVal.textContent = String(wordCount);
          regen();
        },
      });
      optionsHost.appendChild(
        el(
          'div',
          { class: 'field' },
          el('label', { class: 'field-label' }, el('span', null, t(lang, 'genWords')), wcVal),
          range
        )
      );
    }
  };

  const tabPwd = el('button', { type: 'button', class: 'seg-btn is-active' }, t(lang, 'genModePassword'));
  const tabPhrase = el('button', { type: 'button', class: 'seg-btn' }, t(lang, 'genModePassphrase'));

  tabPwd.addEventListener('click', () => {
    mode = 'password';
    tabPwd.classList.add('is-active');
    tabPhrase.classList.remove('is-active');
    renderOptions();
    regen();
  });
  tabPhrase.addEventListener('click', () => {
    mode = 'passphrase';
    tabPhrase.classList.add('is-active');
    tabPwd.classList.remove('is-active');
    renderOptions();
    regen();
  });

  renderOptions();
  regen();

  const content = el(
    'div',
    { class: 'settings-group' },
    el('div', { class: 'segmented' }, tabPwd, tabPhrase),
    previewNode,
    meterWrap,
    el(
      'div',
      { class: 'form-grid-2' },
      el(
        'button',
        { type: 'button', class: 'btn', onClick: () => { triggerHaptic(12); regen(); } },
        svgIcon('refresh', 18),
        t(lang, 'generateBtn')
      ),
      el(
        'button',
        {
          type: 'button',
          class: 'btn',
          onClick: async () => {
            try {
              await session.clipboard.copySecret(currentValue, session.settings?.clipboardClearSec ?? 30);
              triggerHaptic();
              showToast(t(lang, 'copiedToast'), 'success');
            } catch {
              showToast(t(lang, 'copiedToast'), 'warn');
            }
          },
        },
        svgIcon('copy', 18),
        t(lang, 'copyPass')
      )
    ),
    optionsHost,
    onSelect
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary btn-block',
            onClick: () => {
              onSelect(currentValue);
              sheet.close();
            },
          },
          svgIcon('check', 18),
          t(lang, 'genUse')
        )
      : null
  );

  const sheet = openBottomSheet({ title: t(lang, 'generatorTitle'), content });
  return sheet;
}
