/**
 * Khazna Onboarding (Pattern / Optional Password / Transfer from Old Device) & Unlock View
 */

import { evaluatePasswordStrength, MIN_MASTER_PASSWORD_LEN } from '../crypto/vault-crypto.js';
import { formatError, t } from '../i18n/strings.js';
import { clearNode, el, showToast, svgIcon, triggerHaptic } from './dom.js';
import { createPatternPad } from './pattern-pad.js';

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
 * Renders either the Vault Creation / Old-Device Transfer screen,
 * the One-Time Recovery Key confirmation screen,
 * or the Locked Vault Unlock screen (Pattern + Optional Password + Biometric + Recovery Key).
 */
export function renderUnlockView({
  session,
  lang,
  onToggleLang,
  onDownloadZip = null,
  hasPendingSync = false,
  pendingSyncCode = '',
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

  // --- STATE 2: Create New Vault (Pattern Default | Optional Password | Transfer from Old Device) ---
  if (!session.hasVault) {
    let createMode = hasPendingSync ? 'transfer' : 'pattern'; // 'pattern' | 'password' | 'transfer'
    const card = el('section', { class: 'glass-card auth-card' });

    const renderCreateCard = () => {
      clearNode(card);
      const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });

      const tabPattern = el(
        'button',
        {
          type: 'button',
          class: `seg-btn ${createMode === 'pattern' ? 'is-active' : ''}`.trim(),
          onClick: () => {
            createMode = 'pattern';
            renderCreateCard();
          },
        },
        t(lang, 'patternTabLabel')
      );
      const tabPassword = el(
        'button',
        {
          type: 'button',
          class: `seg-btn ${createMode === 'password' ? 'is-active' : ''}`.trim(),
          onClick: () => {
            createMode = 'password';
            renderCreateCard();
          },
        },
        t(lang, 'passwordTabLabel')
      );

      card.appendChild(topTools);
      card.appendChild(
        el(
          'div',
          { class: 'auth-hero' },
          el('div', { class: 'auth-hero-icon' }, svgIcon(createMode === 'transfer' ? 'link' : 'shield', 32)),
          el('h1', null, createMode === 'transfer' ? t(lang, 'transferFromOldTitle') : t(lang, 'createVaultTitle')),
          el('p', null, createMode === 'transfer' ? t(lang, 'transferFromOldSub') : t(lang, 'createVaultSubtitle'))
        )
      );

      if (createMode !== 'transfer') {
        card.appendChild(el('div', { class: 'segmented' }, tabPattern, tabPassword));
      }
      card.appendChild(errBox);

      if (createMode === 'pattern') {
        let firstSecret = null;
        const pad = createPatternPad({
          lang,
          hint: t(lang, 'patternDrawFirst'),
          onComplete: async (secret) => {
            errBox.classList.add('hidden');
            if (!firstSecret) {
              firstSecret = secret;
              pad.setSuccess(t(lang, 'patternDrawConfirm'));
              setTimeout(() => pad.reset(t(lang, 'patternDrawConfirm')), 350);
              return;
            }
            if (secret !== firstSecret) {
              firstSecret = null;
              pad.setError(t(lang, 'patternMismatch'));
              errBox.textContent = t(lang, 'patternMismatch');
              errBox.classList.remove('hidden');
              return;
            }
            pad.setDisabled(true);
            pad.setSuccess(t(lang, 'calibratingKdf'));
            try {
              const res = await session.createVault({ masterPassword: secret });
              onRecoveryConfirmed && onRecoveryConfirmed(res.recoveryKeyFormatted);
            } catch (err) {
              firstSecret = null;
              pad.setDisabled(false);
              pad.setError(formatError(err, lang));
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove('hidden');
            }
          },
        });
        card.appendChild(pad.wrap);
      } else if (createMode === 'password') {
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
        card.appendChild(form);
      } else {
        // --- Transfer from Old Device via Code (using same Pattern or Password!) ---
        let transferLockMode = 'pattern'; // 'pattern' | 'password'
        const codeIn = el('textarea', {
          class: 'textarea ltr-value mono',
          rows: 3,
          autocomplete: 'off',
          spellcheck: 'false',
          value: pendingSyncCode || '',
          placeholder: t(lang, 'syncReceivePlaceholder'),
        });

        const lockHost = el('div', { class: 'settings-group' });
        const segPat = el('button', { type: 'button', class: 'seg-btn is-active' }, t(lang, 'patternTabLabel'));
        const segPwd = el('button', { type: 'button', class: 'seg-btn' }, t(lang, 'passwordTabLabel'));

        const runTransfer = async (secret, onFail) => {
          errBox.classList.add('hidden');
          const code = codeIn.value.trim();
          if (!code) {
            const msg = lang === 'en' ? 'Paste the transfer code from your old device first.' : 'الصق كود النقل من جهازك القديم أولاً.';
            errBox.textContent = msg;
            errBox.classList.remove('hidden');
            if (onFail) onFail(msg);
            return;
          }
          try {
            const res = await session.createVaultFromSyncCode({
              syncInput: code,
              secret,
              enforceMinimums: true,
            });
            showToast(
              `${t(lang, 'syncSuccessToast')} (+${res.summary.added})`,
              'success',
              3800
            );
            onRecoveryConfirmed && onRecoveryConfirmed(res.recoveryKeyFormatted);
          } catch (err) {
            const msg = formatError(err, lang);
            errBox.textContent = msg;
            errBox.classList.remove('hidden');
            if (onFail) onFail(msg);
          }
        };

        const renderTransferLock = () => {
          clearNode(lockHost);
          segPat.classList.toggle('is-active', transferLockMode === 'pattern');
          segPwd.classList.toggle('is-active', transferLockMode === 'password');

          if (transferLockMode === 'pattern') {
            const pad = createPatternPad({
              lang,
              hint: lang === 'en' ? 'Draw the SAME pattern used on your old device' : 'ارسم نفس النمط المستخدم على جهازك القديم',
              onComplete: async (secret) => {
                pad.setDisabled(true);
                pad.setSuccess(t(lang, 'calibratingKdf'));
                await runTransfer(secret, (msg) => {
                  pad.setDisabled(false);
                  pad.setError(msg);
                });
              },
            });
            lockHost.appendChild(pad.wrap);
          } else {
            const pwdIn = el('input', {
              type: 'password',
              class: 'input ltr-value',
              autocomplete: 'off',
              spellcheck: 'false',
              placeholder: lang === 'en' ? 'Same password as old device' : 'نفس كلمة مرور الجهاز القديم',
              required: true,
            });
            const goBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, svgIcon('link', 17), t(lang, 'transferStartBtn'));
            const tForm = el(
              'form',
              {
                onSubmit: async (e) => {
                  e.preventDefault();
                  goBtn.disabled = true;
                  goBtn.textContent = t(lang, 'unlocking');
                  await runTransfer(pwdIn.value, () => {
                    goBtn.disabled = false;
                    goBtn.textContent = t(lang, 'transferStartBtn');
                  });
                },
              },
              el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'syncPassLabel')), pwdIn),
              goBtn
            );
            lockHost.appendChild(tForm);
          }
        };

        segPat.addEventListener('click', () => { transferLockMode = 'pattern'; renderTransferLock(); });
        segPwd.addEventListener('click', () => { transferLockMode = 'password'; renderTransferLock(); });
        renderTransferLock();

        card.appendChild(
          el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'syncReceiveCodeLabel')), codeIn)
        );
        card.appendChild(el('div', { class: 'segmented' }, segPat, segPwd));
        card.appendChild(lockHost);
      }

      // Toggle button between Create New & Transfer from Old Device
      card.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-ghost btn-block',
            onClick: () => {
              createMode = createMode === 'transfer' ? 'pattern' : 'transfer';
              renderCreateCard();
            },
          },
          svgIcon(createMode === 'transfer' ? 'shield' : 'link', 17),
          createMode === 'transfer' ? t(lang, 'createVaultTitle') : t(lang, 'transferFromOldBtn')
        )
      );
    };

    renderCreateCard();
    screen.appendChild(card);
    return screen;
  }

  // --- STATE 3: Unlock Existing Vault ---
  let mode = session.hasPatternUnlock ? 'pattern' : 'password'; // 'pattern' | 'password' | 'recovery'
  const card = el('section', { class: 'glass-card auth-card' });

  const renderUnlockCard = () => {
    clearNode(card);
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

    if (mode === 'pattern') {
      const pad = createPatternPad({
        lang,
        hint: t(lang, 'patternDrawUnlock'),
        onComplete: async (secret) => {
          errBox.classList.add('hidden');
          pad.setDisabled(true);
          pad.setSuccess(t(lang, 'unlocking'));
          try {
            await session.unlockWithPassword(secret);
          } catch (err) {
            pad.setDisabled(false);
            pad.setError(formatError(err, lang));
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove('hidden');
          }
        },
      });
      card.appendChild(pad.wrap);

      if (bioState.enabled) {
        appendBioButton(card, bioState, session, lang, errBox);
      }

      if (session.hasPasswordUnlock) {
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
            svgIcon('key', 17),
            t(lang, 'usePasswordUnlock')
          )
        );
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
          svgIcon('key', 17),
          t(lang, 'useRecoveryKey')
        )
      );
    } else if (mode === 'password') {
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
        appendBioButton(card, bioState, session, lang, errBox);
      }

      if (session.hasPatternUnlock) {
        card.appendChild(
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-ghost btn-block',
              onClick: () => {
                mode = 'pattern';
                renderUnlockCard();
              },
            },
            t(lang, 'usePatternUnlock')
          )
        );
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
              mode = session.hasPatternUnlock ? 'pattern' : 'password';
              renderUnlockCard();
            },
          },
          session.hasPatternUnlock ? t(lang, 'usePatternUnlock') : t(lang, 'backToPassword')
        )
      );
    }
  };

  renderUnlockCard();
  screen.appendChild(card);
  return screen;
}

function appendBioButton(card, bioState, session, lang, errBox) {
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
            ? 'Convenience biometric mode requires your lock after cold start or 24h.'
            : 'وضع البصمة السريع يتطلب النمط أو كلمة المرور بعد إعادة التشغيل أو كل ٢٤ ساعة.'
        )
      )
    );
  }
}
