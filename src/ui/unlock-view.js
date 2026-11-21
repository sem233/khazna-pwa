/**
 * Khazna Onboarding (Create Vault + One-Time Recovery Key) & Unlock View
 */

import { evaluatePasswordStrength, MIN_MASTER_PASSWORD_LEN } from '../crypto/vault-crypto.js';
import { formatError, t } from '../i18n/strings.js';
import { el, showToast, svgIcon, triggerHaptic } from './dom.js';

function createStrengthMeter(lang) {
  const bars = el(
    'div',
    { class: 'strength-bars', 'aria-hidden': 'true' },
    el('div', { class: 'strength-bar' }),
    el('div', { class: 'strength-bar' }),
    el('div', { class: 'strength-bar' }),
    el('div', { class: 'strength-bar' })
  );
  const labelNode = el('span', null, '');
  const bitsNode = el('span', { class: 'ltr-inline mono' }, '');
  const wrap = el(
    'div',
    { class: 'strength-meter' },
    bars,
    el('div', { class: 'strength-caption' }, labelNode, bitsNode)
  );

  const update = (pwd) => {
    if (!pwd) {
      wrap.className = 'strength-meter';
      labelNode.textContent = '';
      bitsNode.textContent = '';
      return;
    }
    const res = evaluatePasswordStrength(pwd);
    wrap.className = `strength-meter strength-${res.score}`;
    labelNode.textContent = lang === 'en' ? `${res.labelEn} — ${res.feedbackEn}` : `${res.labelAr} — ${res.feedbackAr}`;
    bitsNode.textContent = `${res.entropyBits} bits`;
  };

  return { wrap, update };
}

/**
 * Renders either the Vault Creation screen, the One-Time Recovery Key confirmation screen,
 * or the Locked Vault Unlock screen (Master Password + Biometric + Recovery Key).
 */
export function renderUnlockView({
  session,
  lang,
  onToggleLang,
  onDownloadZip = null,
  hasPendingSync = false,
  pendingRecoveryKey = null,
  onRecoveryConfirmed = null,
}) {
  const screen = el('main', { class: 'auth-screen view-enter' });

  const langBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-sm',
      'aria-label': t(lang, 'langLabel'),
      onClick: onToggleLang,
    },
    lang === 'ar' ? 'English' : 'العربية'
  );

  const zipBtn = onDownloadZip
    ? el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm',
          'aria-label': t(lang, 'downloadZipBtn'),
          title: t(lang, 'downloadZipBtn'),
          'data-testid': 'auth-download-zip',
          onClick: onDownloadZip,
        },
        svgIcon('download', 15),
        t(lang, 'downloadZipShort')
      )
    : null;

  const topTools = el('div', { class: 'toolbar-row' }, langBtn, zipBtn);

  // --- STATE 1: Show One-Time Recovery Key immediately after Vault creation ---
  if (pendingRecoveryKey) {
    const savedCheckbox = el('input', { type: 'checkbox', id: 'recovery-saved-check' });
    const enterBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-primary btn-block',
        disabled: true,
        onClick: () => onRecoveryConfirmed && onRecoveryConfirmed(),
      },
      t(lang, 'enterVaultBtn')
    );

    savedCheckbox.addEventListener('change', () => {
      enterBtn.disabled = !savedCheckbox.checked;
    });

    const card = el(
      'section',
      { class: 'glass-card auth-card recovery-print-box' },
      el(
        'div',
        { class: 'auth-hero' },
        el('div', { class: 'auth-hero-icon' }, svgIcon('key', 30)),
        el('h1', null, t(lang, 'recoveryModalTitle')),
        el('p', null, t(lang, 'recoveryModalWarn'))
      ),
      el('div', { class: 'recovery-key-display', 'data-testid': 'recovery-key-box' }, pendingRecoveryKey),
      el(
        'div',
        { class: 'form-grid-2 no-print' },
        el(
          'button',
          {
            type: 'button',
            class: 'btn',
            onClick: async () => {
              try {
                await session.clipboard.copySecret(pendingRecoveryKey, 0);
                triggerHaptic();
                showToast(t(lang, 'copiedToast'), 'success');
              } catch {
                showToast(t(lang, 'copyRecoveryKey'), 'warn');
              }
            },
          },
          svgIcon('copy', 18),
          t(lang, 'copyRecoveryKey')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn',
            onClick: () => window.print(),
          },
          t(lang, 'printRecoveryKey')
        )
      ),
      el(
        'label',
        { class: 'checkbox-row no-print', for: 'recovery-saved-check' },
        savedCheckbox,
        el('span', null, t(lang, 'recoverySavedCheckbox'))
      ),
      enterBtn
    );

    screen.appendChild(card);
    return screen;
  }

  // --- STATE 2: Create New Vault ---
  if (!session.hasVault) {
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const pwdInput = el('input', {
      id: 'create-master-pwd',
      type: 'password',
      class: 'input ltr-value',
      autocomplete: 'off',
      spellcheck: 'false',
      minlength: MIN_MASTER_PASSWORD_LEN,
      required: true,
    });
    const confirmInput = el('input', {
      id: 'confirm-master-pwd',
      type: 'password',
      class: 'input ltr-value',
      autocomplete: 'off',
      spellcheck: 'false',
      required: true,
    });

    const meter = createStrengthMeter(lang);
    pwdInput.addEventListener('input', () => meter.update(pwdInput.value));

    const toggleEye = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-icon',
        'aria-label': t(lang, 'holdToReveal'),
        onClick: () => {
          const next = pwdInput.type === 'password' ? 'text' : 'password';
          pwdInput.type = next;
          confirmInput.type = next;
        },
      },
      svgIcon('eye', 18)
    );

    const submitBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, t(lang, 'createVaultBtn'));

    const form = el(
      'form',
      {
        onSubmit: async (e) => {
          e.preventDefault();
          errBox.classList.add('hidden');
          const pwd = pwdInput.value;
          const conf = confirmInput.value;

          if (Array.from(pwd).length < MIN_MASTER_PASSWORD_LEN) {
            errBox.textContent = lang === 'en'
              ? `Master password must be at least ${MIN_MASTER_PASSWORD_LEN} characters.`
              : `يجب ألا تقل كلمة المرور الرئيسية عن ${MIN_MASTER_PASSWORD_LEN} حرفاً.`;
            errBox.classList.remove('hidden');
            return;
          }
          if (pwd !== conf) {
            errBox.textContent = t(lang, 'passwordsMismatch');
            errBox.classList.remove('hidden');
            return;
          }

          submitBtn.disabled = true;
          submitBtn.textContent = t(lang, 'calibratingKdf');
          try {
            const res = await session.createVault({ masterPassword: pwd });
            pwdInput.value = '';
            confirmInput.value = '';
            onRecoveryConfirmed && onRecoveryConfirmed(res.recoveryKeyFormatted);
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove('hidden');
            submitBtn.disabled = false;
            submitBtn.textContent = t(lang, 'createVaultBtn');
          }
        },
      },
      errBox,
      el(
        'div',
        { class: 'field' },
        el('label', { class: 'field-label', for: 'create-master-pwd' }, t(lang, 'masterPasswordLabel')),
        el('div', { class: 'input-row' }, pwdInput, toggleEye),
        meter.wrap
      ),
      el(
        'div',
        { class: 'field' },
        el('label', { class: 'field-label', for: 'confirm-master-pwd' }, t(lang, 'confirmPasswordLabel')),
        confirmInput
      ),
      el('div', { class: 'banner banner-info' }, el('span', null, t(lang, 'noHintNote'))),
      el('div', { class: 'field' }),
      submitBtn
    );

    const card = el(
      'section',
      { class: 'glass-card auth-card' },
      topTools,
      el(
        'div',
        { class: 'auth-hero' },
        el('div', { class: 'auth-hero-icon' }, svgIcon('shield', 32)),
        el('h1', null, t(lang, 'createVaultTitle')),
        el('p', null, t(lang, 'createVaultSubtitle'))
      ),
      hasPendingSync
        ? el('div', { class: 'banner banner-info', 'data-testid': 'pending-sync-banner' }, el('span', null, t(lang, 'syncPendingUnlockBanner')))
        : null,
      form
    );

    screen.appendChild(card);
    return screen;
  }

  // --- STATE 3: Unlock Existing Vault ---
  let mode = 'password'; // 'password' | 'recovery'
  const card = el('section', { class: 'glass-card auth-card' });

  const renderUnlockCard = () => {
    while (card.firstChild) card.removeChild(card.firstChild);
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const bioState = session.getBiometricState();
    const lockoutMs = session.getLockoutRemainingMs();

    if (lockoutMs > 0) {
      const secs = Math.ceil(lockoutMs / 1000);
      errBox.textContent = lang === 'en'
        ? `Too many failed attempts. Try again in ${secs}s.`
        : `محاولات فاشلة متكررة. حاول مجدداً بعد ${secs} ثانية.`;
      errBox.classList.remove('hidden');
    }

    card.appendChild(topTools);
    card.appendChild(
      el(
        'div',
        { class: 'auth-hero' },
        el('div', { class: 'auth-hero-icon' }, svgIcon('lock', 30)),
        el('h1', null, t(lang, 'lockedTitle')),
        el('p', null, t(lang, 'lockedSubtitle'))
      )
    );
    if (hasPendingSync) {
      card.appendChild(
        el('div', { class: 'banner banner-info', 'data-testid': 'pending-sync-banner' }, el('span', null, t(lang, 'syncPendingUnlockBanner')))
      );
    }
    card.appendChild(errBox);

    if (mode === 'password') {
      const pwdInput = el('input', {
        id: 'unlock-master-pwd',
        type: 'password',
        class: 'input ltr-value',
        autocomplete: 'off',
        spellcheck: 'false',
        required: true,
        placeholder: '••••••••••••',
      });
      const submitBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, t(lang, 'unlockBtn'));

      const form = el(
        'form',
        {
          onSubmit: async (e) => {
            e.preventDefault();
            errBox.classList.add('hidden');
            submitBtn.disabled = true;
            submitBtn.textContent = t(lang, 'unlocking');
            try {
              await session.unlockWithPassword(pwdInput.value);
              pwdInput.value = '';
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove('hidden');
              submitBtn.disabled = false;
              submitBtn.textContent = t(lang, 'unlockBtn');
            }
          },
        },
        el(
          'div',
          { class: 'field' },
          el('label', { class: 'field-label', for: 'unlock-master-pwd' }, t(lang, 'masterPasswordLabel')),
          pwdInput
        ),
        submitBtn
      );

      card.appendChild(form);

      if (bioState.enabled) {
        const isNative = bioState.mode === 'native';
        const bioLabel = isNative
          ? (lang === 'en' ? 'Unlock with Fingerprint' : 'فتح ببصمة الإصبع')
          : t(lang, 'unlockWithFingerprint');

        const bioBtn = el(
          'button',
          {
            type: 'button',
            class: `btn btn-block ${isNative ? 'btn-primary' : ''}`.trim(),
            disabled: !bioState.ready,
            onClick: async () => {
              errBox.classList.add('hidden');
              try {
                await session.unlockWithBiometric();
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove('hidden');
              }
            },
          },
          svgIcon('fingerprint', 20),
          bioLabel
        );
        card.appendChild(bioBtn);

        if (bioState.mode === 'convenience' && !bioState.ready) {
          card.appendChild(
            el(
              'div',
              { class: 'banner banner-warn' },
              el(
                'span',
                null,
                lang === 'en'
                  ? 'Convenience biometric mode requires Master Password after cold start or 24h.'
                  : 'وضع البصمة السريع يتطلب كلمة المرور الرئيسية بعد إعادة التشغيل أو كل ٢٤ ساعة.'
              )
            )
          );
        }
      }

      card.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost btn-block',
            onClick: () => {
              mode = 'recovery';
              renderUnlockCard();
            },
          },
          svgIcon('key', 18),
          t(lang, 'useRecoveryKey')
        )
      );
    } else {
      const recInput = el('textarea', {
        id: 'unlock-recovery-key',
        class: 'textarea ltr-value',
        autocomplete: 'off',
        spellcheck: 'false',
        placeholder: 'XXXX-XXXX-XXXX-...',
        required: true,
      });
      const newPwdInput = el('input', {
        id: 'recovery-new-master',
        type: 'password',
        class: 'input ltr-value',
        autocomplete: 'off',
        spellcheck: 'false',
        placeholder: t(lang, 'newMasterOptional'),
      });
      const submitBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, t(lang, 'unlockBtn'));

      const form = el(
        'form',
        {
          onSubmit: async (e) => {
            e.preventDefault();
            errBox.classList.add('hidden');
            submitBtn.disabled = true;
            submitBtn.textContent = t(lang, 'unlocking');
            try {
              const nextMaster = newPwdInput.value.trim() || null;
              await session.unlockWithRecoveryKey(recInput.value, nextMaster);
              recInput.value = '';
              newPwdInput.value = '';
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove('hidden');
              submitBtn.disabled = false;
              submitBtn.textContent = t(lang, 'unlockBtn');
            }
          },
        },
        el(
          'div',
          { class: 'field' },
          el('label', { class: 'field-label', for: 'unlock-recovery-key' }, t(lang, 'recoveryInputLabel')),
          recInput
        ),
        el(
          'div',
          { class: 'field' },
          el('label', { class: 'field-label', for: 'recovery-new-master' }, t(lang, 'newMasterOptional')),
          newPwdInput
        ),
        submitBtn
      );

      card.appendChild(form);
      card.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost btn-block',
            onClick: () => {
              mode = 'password';
              renderUnlockCard();
            },
          },
          t(lang, 'backToPassword')
        )
      );
    }
  };

  renderUnlockCard();
  screen.appendChild(card);
  return screen;
}
