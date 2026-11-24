/**
 * Khazna Settings View
 *
 * - Language (Arabic RTL / English LTR) & Theme (Dark / Light / AMOLED) & Low-End Blur
 * - Security: Auto-lock, BG grace, Clipboard clear (+ honest platform note), Copy Combo mode,
 *   Re-auth sensitive actions, WebAuthn PRF / Honest Convenience setup, Change Master Password,
 *   Rotate Recovery Key, Optional Wipe-after-N-failures
 * - Data: Local Import/Export launcher, Vault Health Check, Rolling Encrypted Snapshots restore
 * - PWA & Integrity: In-App Install Prompt button (with iOS fallback), User-Gated SW Update activator,
 *   Persistent Storage status, App Version & App-Shell SHA-256 hash, Honest Screenshot Warning, Wipe Vault
 */

import { formatError, t } from '../i18n/strings.js';
import { clearNode, el, openBottomSheet, requestReauth, showToast, svgIcon } from './dom.js';
import { createPatternPad } from './pattern-pad.js';

export function renderSettingsView({
  session,
  lang,
  storageStatus,
  integrityInfo,
  snapshots,
  pwaState,
  onOpenImportExport,
  onOpenSync,
  onDownloadZip,
  isNativeAndroid = false,
  onRefresh,
  onApplySettings,
  onActivateUpdate,
  onInstallPwa,
}) {
  const container = el('div', { class: 'settings-group view-enter' });
  const settings = session.settings || {};
  const bioState = session.getBiometricState();

  // --- 1) Appearance & Language ---
  const langSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'langLabel'),
      onChange: async (e) => {
        await session.updateSettings({ lang: e.target.value });
        onApplySettings();
      },
    },
    el('option', { value: 'ar', selected: lang === 'ar' }, 'العربية (RTL)'),
    el('option', { value: 'en', selected: lang === 'en' }, 'English (LTR)')
  );

  const themeSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'themeLabel'),
      onChange: async (e) => {
        await session.updateSettings({ theme: e.target.value });
        onApplySettings();
      },
    },
    el('option', { value: 'dark', selected: settings.theme === 'dark' }, t(lang, 'themeDark')),
    el('option', { value: 'light', selected: settings.theme === 'light' }, t(lang, 'themeLight')),
    el('option', { value: 'amoled', selected: settings.theme === 'amoled' }, t(lang, 'themeAmoled'))
  );

  const comboSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'copyComboModeLabel'),
      onChange: async (e) => {
        await session.updateSettings({ copyComboMode: e.target.value });
        showToast(t(lang, 'save'), 'success');
      },
    },
    el('option', { value: 'two-step', selected: settings.copyComboMode !== 'one-tap' }, t(lang, 'comboTwoStep')),
    el('option', { value: 'one-tap', selected: settings.copyComboMode === 'one-tap' }, t(lang, 'comboOneTap'))
  );

  container.appendChild(
    el(
      'section',
      { class: 'glass-card settings-group' },
      el('h2', { class: 'sheet-title' }, t(lang, 'settingsAppearance')),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'langLabel')), langSel),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'themeLabel')), themeSel),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'copyComboModeLabel')), comboSel)
    )
  );

  // --- 2) Security & Lock ---
  const autoLockSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'autoLockLabel'),
      onChange: async (e) => {
        await session.updateSettings({ autoLockSec: parseInt(e.target.value, 10) });
        showToast(t(lang, 'save'), 'success');
      },
    },
    ...[30, 60, 120, 300, 600, 900].map((sec) =>
      el(
        'option',
        { value: sec, selected: (settings.autoLockSec ?? 120) === sec },
        sec < 60 ? `${sec} ${t(lang, 'seconds')}` : `${sec / 60} ${t(lang, 'minutes')}`
      )
    )
  );

  const bgGraceSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'bgGraceLabel'),
      onChange: async (e) => {
        await session.updateSettings({ bgGraceSec: parseInt(e.target.value, 10) });
        showToast(t(lang, 'save'), 'success');
      },
    },
    ...[0, 15, 30, 60].map((sec) =>
      el('option', { value: sec, selected: (settings.bgGraceSec ?? 15) === sec }, `${sec} ${t(lang, 'seconds')}`)
    )
  );

  const clipSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'clipboardClearLabel'),
      onChange: async (e) => {
        await session.updateSettings({ clipboardClearSec: parseInt(e.target.value, 10) });
        showToast(t(lang, 'save'), 'success');
      },
    },
    ...[0, 15, 30, 60].map((sec) =>
      el('option', { value: sec, selected: (settings.clipboardClearSec ?? 30) === sec }, sec === 0 ? (lang === 'en' ? 'Off' : 'معطّل') : `${sec} ${t(lang, 'seconds')}`)
    )
  );

  const reauthCheck = el('input', {
    type: 'checkbox',
    checked: settings.reauthSensitive !== false,
    onChange: async (e) => {
      await session.updateSettings({ reauthSensitive: e.target.checked });
    },
  });

  const privacyBlurCheck = el('input', {
    type: 'checkbox',
    checked: settings.privacyBlurOnBlur === true,
    onChange: async (e) => {
      await session.updateSettings({ privacyBlurOnBlur: e.target.checked });
    },
  });

  const wipeSel = el(
    'select',
    {
      class: 'select',
      'aria-label': t(lang, 'wipeAfterLabel'),
      onChange: async (e) => {
        const val = parseInt(e.target.value, 10);
        if (val > 0) {
          const ok = await requestReauth({ session, lang });
          if (!ok) {
            e.target.value = String(session.header?.security?.wipeAfterFailures || 0);
            return;
          }
        }
        await session.setWipeAfterFailures(val);
        showToast(t(lang, 'save'), val > 0 ? 'warn' : 'success');
      },
    },
    el('option', { value: 0, selected: !(session.header?.security?.wipeAfterFailures) }, t(lang, 'wipeAfterOff')),
    el('option', { value: 5, selected: session.header?.security?.wipeAfterFailures === 5 }, '5'),
    el('option', { value: 10, selected: session.header?.security?.wipeAfterFailures === 10 }, '10')
  );

  const bioDesc = bioState.enabled
    ? bioState.mode === 'native'
      ? (lang === 'en' ? 'Native Android Biometric (Active)' : 'بصمة أندرويد الحقيقية (مفعّلة)')
      : bioState.mode === 'prf'
        ? t(lang, 'biometricPrfActive')
        : t(lang, 'biometricConvActive')
    : t(lang, 'biometricOff');

  const bioActionBtn = bioState.enabled
    ? el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm btn-danger',
          onClick: async () => {
            await session.disableBiometric();
            showToast(t(lang, 'disableBiometric'), 'info');
            await onRefresh();
          },
        },
        t(lang, 'disableBiometric')
      )
    : el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm btn-primary',
          onClick: () => openBiometricSetupSheet({ session, lang, onDone: onRefresh }),
        },
        svgIcon('fingerprint', 16),
        t(lang, 'enableBiometric')
      );

  container.appendChild(
    el(
      'section',
      { class: 'glass-card settings-group' },
      el('h2', { class: 'sheet-title' }, t(lang, 'settingsSecurity')),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'autoLockLabel')), autoLockSel),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'bgGraceLabel')), bgGraceSel),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'clipboardClearLabel')), clipSel),
      el('div', { class: 'banner banner-info' }, el('span', null, t(lang, 'clipboardLimitNote'))),
      el('label', { class: 'checkbox-row' }, reauthCheck, el('span', null, t(lang, 'reauthLabel'))),
      !isNativeAndroid
        ? el('label', { class: 'checkbox-row' }, privacyBlurCheck, el('span', null, t(lang, 'privacyBlurLabel')))
        : null,
      el(
        'div',
        { class: 'settings-row' },
        el('div', { class: 'settings-row-info' }, el('div', { class: 'settings-row-title' }, t(lang, 'biometricTitle')), el('div', { class: 'settings-row-desc' }, bioDesc)),
        bioActionBtn
      ),
      el('div', { class: 'settings-row' }, el('span', { class: 'settings-row-title' }, t(lang, 'wipeAfterLabel')), wipeSel),
      el(
        'div',
        { class: 'form-grid-2' },
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary',
            onClick: () => openSetPatternSheet({ session, lang, onDone: onRefresh }),
          },
          svgIcon('lock', 16),
          t(lang, 'changePatternBtn')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn',
            onClick: () => openChangeMasterPasswordSheet({ session, lang, onDone: onRefresh }),
          },
          svgIcon('key', 16),
          session.hasPasswordUnlock ? t(lang, 'changeMasterPwd') : t(lang, 'addOptionalPasswordBtn')
        )
      ),
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-block',
          onClick: () => openRotateRecoverySheet({ session, lang }),
        },
        svgIcon('refresh', 16),
        t(lang, 'rotateRecoveryKey')
      )
    )
  );

  // --- 3) Data, Health Check & Rolling Encrypted Snapshots ---
  const healthResultNode = el('div', { class: 'banner hidden' });

  const snapList = el('div', { class: 'settings-group' });
  if (snapshots.length === 0) {
    snapList.appendChild(el('span', { class: 'settings-row-desc' }, lang === 'en' ? 'No snapshots yet.' : 'لا توجد لقطات بعد.'));
  } else {
    for (const s of snapshots) {
      snapList.appendChild(
        el(
          'div',
          { class: 'settings-row' },
          el(
            'div',
            { class: 'settings-row-info' },
            el('div', { class: 'settings-row-title' }, `${s.reason} (${s.recordCount})`),
            el('div', { class: 'settings-row-desc' }, new Date(s.createdAt).toLocaleString(lang === 'en' ? 'en' : 'ar'))
          ),
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-sm',
              onClick: async () => {
                const ok = await requestReauth({ session, lang });
                if (!ok) return;
                await session.storage.restoreSnapshot(s.id);
                showToast(t(lang, 'restoreSnapshot'), 'success');
                await onRefresh();
              },
            },
            t(lang, 'restoreSnapshot')
          )
        )
      );
    }
  }

  container.appendChild(
    el(
      'section',
      { class: 'glass-card settings-group' },
      el('h2', { class: 'sheet-title' }, t(lang, 'settingsData')),
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-primary btn-block',
          'data-testid': 'settings-sync-btn',
          onClick: onOpenSync,
        },
        svgIcon('link', 17),
        t(lang, 'syncSettingsBtn')
      ),
      el(
        'div',
        { class: 'form-grid-2' },
        el('button', { type: 'button', class: 'btn', onClick: onOpenImportExport }, svgIcon('download', 17), t(lang, 'importExportBtn')),
        el(
          'button',
          {
            type: 'button',
            class: 'btn',
            onClick: async () => {
              const report = await session.runHealthCheck();
              healthResultNode.className = `banner ${report.ok ? 'banner-success' : 'banner-danger'}`;
              healthResultNode.textContent = report.ok
                ? (lang === 'en' ? `Health Check Passed: ${report.valid}/${report.total} records decrypted & authenticated.` : `نجح الفحص: تم فك تشفير والتحقق من ${report.valid}/${report.total} سجل بنجاح ✓`)
                : (lang === 'en' ? `Corrupted records detected: ${report.corrupted.length}` : `تم اكتشاف ${report.corrupted.length} سجل تالف!`);
            },
          },
          svgIcon('shield', 17),
          t(lang, 'healthCheckBtn')
        )
      ),
      healthResultNode,
      el('h3', { class: 'settings-row-title' }, t(lang, 'snapshotsTitle')),
      snapList
    )
  );

  // --- 4) PWA, Persistent Storage, App-Shell Integrity & Danger Zone ---
  const pwaCard = el('section', { class: 'glass-card settings-group' }, el('h2', { class: 'sheet-title' }, t(lang, 'settingsPwa')));

  if (pwaState.updateWaiting) {
    pwaCard.appendChild(
      el(
        'div',
        { class: 'banner banner-info' },
        el('span', null, t(lang, 'updateAvailable')),
        el('button', { type: 'button', class: 'btn btn-sm btn-primary', onClick: onActivateUpdate }, t(lang, 'updateConfirmBtn'))
      )
    );
  }

  if (!isNativeAndroid && !pwaState.isInstalled) {
    if (pwaState.canInstall) {
      pwaCard.appendChild(
        el('button', { type: 'button', class: 'btn btn-primary btn-block', onClick: onInstallPwa }, svgIcon('download', 17), t(lang, 'installAppBtn'))
      );
    } else if (pwaState.isIOS) {
      pwaCard.appendChild(el('div', { class: 'banner banner-info' }, el('span', null, t(lang, 'installIosHint'))));
    }
  }

  if (onDownloadZip) {
    pwaCard.appendChild(
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-block',
          'data-testid': 'settings-download-zip',
          onClick: onDownloadZip,
        },
        svgIcon('download', 17),
        t(lang, 'downloadZipBtn')
      )
    );
  }

  const kdfInfo = session.header
    ? `${session.header.kdf} (${JSON.stringify(session.header.kdfParams)})`
    : '—';

  pwaCard.appendChild(
    el(
      'div',
      { class: 'settings-row' },
      el('span', { class: 'settings-row-title' }, t(lang, 'storageStatusLabel')),
      el('span', { class: 'settings-row-desc' }, storageStatus?.persisted ? t(lang, 'storagePersisted') : t(lang, 'storageBestEffort'))
    )
  );
  pwaCard.appendChild(
    el(
      'div',
      { class: 'settings-row' },
      el('span', { class: 'settings-row-title' }, t(lang, 'appVersionLabel')),
      el('span', { class: 'settings-row-desc ltr-inline mono' }, `v${integrityInfo?.version || '2.3.0'} • ${kdfInfo}`)
    )
  );
  pwaCard.appendChild(
    el(
      'div',
      { class: 'field' },
      el('span', { class: 'settings-row-title' }, t(lang, 'appShellHashLabel')),
      el('div', { class: 'hash-box', 'data-testid': 'app-shell-hash' }, integrityInfo?.shellSha256 || 'computing...')
    )
  );
  if (isNativeAndroid) {
    pwaCard.appendChild(
      el(
        'div',
        { class: 'banner banner-success' },
        el(
          'span',
          null,
          lang === 'en'
            ? 'Android FLAG_SECURE active: screenshots and screen recording are blocked by the OS.'
            : 'حماية الشاشة (FLAG_SECURE) مفعّلة على الأندرويد: لقطات الشاشة والتسجيل محظورة على مستوى النظام.'
        )
      )
    );
  }

  // Danger Zone: Wipe Vault
  pwaCard.appendChild(
    el(
      'button',
      {
        type: 'button',
        class: 'btn btn-danger btn-block',
        onClick: () => openWipeVaultSheet({ session, lang }),
      },
      svgIcon('trash', 17),
      t(lang, 'wipeVaultBtn')
    )
  );

  container.appendChild(pwaCard);
  return container;
}

function renderCurrentLockStep({ session, lang, onVerified, submitLabel }) {
  const wrap = el('div', { class: 'settings-group' });
  const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
  let method = session.hasPatternUnlock ? 'pattern' : 'password';

  const draw = () => {
    clearNode(wrap);
    wrap.appendChild(errBox);

    if (method === 'pattern') {
      const pad = createPatternPad({
        lang,
        hint: lang === 'en' ? 'Draw your current pattern to continue' : 'ارسم النمط الحالي للمتابعة',
        onComplete: async (secret) => {
          errBox.classList.add('hidden');
          pad.setDisabled(true);
          try {
            await onVerified(secret);
          } catch (err) {
            pad.setDisabled(false);
            pad.setError(formatError(err, lang));
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove('hidden');
          }
        },
      });
      wrap.appendChild(pad.wrap);
      if (session.hasPasswordUnlock) {
        wrap.appendChild(
          el('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-block', onClick: () => { method = 'password'; draw(); } }, t(lang, 'usePasswordUnlock'))
        );
      }
    } else {
      const pwdIn = el('input', {
        type: 'password',
        class: 'input ltr-value',
        autocomplete: 'off',
        spellcheck: 'false',
        required: true,
        placeholder: t(lang, 'masterPasswordLabel'),
      });
      const submitBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, submitLabel || t(lang, 'confirmBtn'));
      const form = el(
        'form',
        {
          onSubmit: async (e) => {
            e.preventDefault();
            errBox.classList.add('hidden');
            submitBtn.disabled = true;
            try {
              await onVerified(pwdIn.value);
              pwdIn.value = '';
            } catch (err) {
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove('hidden');
              submitBtn.disabled = false;
            }
          },
        },
        el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'masterPasswordLabel')), pwdIn),
        submitBtn
      );
      wrap.appendChild(form);
      if (session.hasPatternUnlock) {
        wrap.appendChild(
          el('button', { type: 'button', class: 'btn btn-ghost btn-sm btn-block', onClick: () => { method = 'pattern'; draw(); } }, t(lang, 'usePatternUnlock'))
        );
      }
    }
  };

  draw();
  return wrap;
}

function openBiometricSetupSheet({ session, lang, onDone }) {
  const body = el('div', { class: 'settings-group' });

  body.appendChild(
    renderCurrentLockStep({
      session,
      lang,
      submitLabel: t(lang, 'enableBiometric'),
      onVerified: async (secret) => {
        const res = await session.enrollBiometricWithPassword(secret);
        if (res.mode === 'prf' || res.mode === 'native') {
          sheet.close();
          showToast(
            res.mode === 'native'
              ? lang === 'en'
                ? 'Native Android Biometric Enabled ✓'
                : 'تم تفعيل بصمة أندرويد بنجاح ✓'
              : t(lang, 'biometricPrfActive'),
            'success'
          );
          onDone && (await onDone());
        } else if (res.mode === 'prf-unavailable') {
          clearNode(body);
          body.appendChild(el('div', { class: 'banner banner-warn' }, el('span', null, lang === 'en' ? res.warningEn : res.warningAr)));
          body.appendChild(
            el(
              'div',
              { class: 'form-grid-2' },
              el('button', { type: 'button', class: 'btn', onClick: () => sheet.close() }, t(lang, 'cancel')),
              el(
                'button',
                {
                  type: 'button',
                  class: 'btn btn-primary',
                  onClick: async () => {
                    await res._armConvenience();
                    sheet.close();
                    showToast(t(lang, 'biometricConvActive'), 'warn', 4200);
                    onDone && (await onDone());
                  },
                },
                lang === 'en' ? 'Enable Convenience Mode' : 'تفعيل وضع الراحة'
              )
            )
          );
        }
      },
    })
  );

  const sheet = openBottomSheet({ title: t(lang, 'biometricTitle'), content: body });
}

function openSetPatternSheet({ session, lang, onDone }) {
  const host = el('div', { class: 'settings-group' });
  const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });

  const showNewPatternStep = (currentSecret) => {
    clearNode(host);
    host.appendChild(errBox);
    let firstSecret = null;

    const pad = createPatternPad({
      lang,
      hint: t(lang, 'patternDrawFirst'),
      onComplete: async (newSecret) => {
        errBox.classList.add('hidden');
        if (!firstSecret) {
          firstSecret = newSecret;
          pad.setSuccess(t(lang, 'patternDrawConfirm'));
          setTimeout(() => pad.reset(t(lang, 'patternDrawConfirm')), 350);
          return;
        }
        if (newSecret !== firstSecret) {
          firstSecret = null;
          pad.setError(t(lang, 'patternMismatch'));
          errBox.textContent = t(lang, 'patternMismatch');
          errBox.classList.remove('hidden');
          return;
        }
        pad.setDisabled(true);
        pad.setSuccess(t(lang, 'save'));
        try {
          if (session.unlockMethod === 'pattern') {
            await session.changeMasterPassword({
              currentPassword: currentSecret,
              newMasterPassword: newSecret,
            });
          } else {
            await session.setSecondaryUnlock({
              currentSecret,
              altSecret: newSecret,
            });
          }
          sheet.close();
          showToast(`${t(lang, 'changePatternBtn')} ✓`, 'success');
          onDone && (await onDone());
        } catch (err) {
          firstSecret = null;
          pad.setDisabled(false);
          pad.setError(formatError(err, lang));
          errBox.textContent = formatError(err, lang);
          errBox.classList.remove('hidden');
        }
      },
    });
    host.appendChild(pad.wrap);
  };

  host.appendChild(
    renderCurrentLockStep({
      session,
      lang,
      submitLabel: t(lang, 'confirmBtn'),
      onVerified: async (secret) => {
        await session.verifyReauth({ masterPassword: secret });
        showNewPatternStep(secret);
      },
    })
  );

  const sheet = openBottomSheet({ title: t(lang, 'changePatternBtn'), content: host });
}

function openChangeMasterPasswordSheet({ session, lang, onDone }) {
  const host = el('div', { class: 'settings-group' });
  const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });

  const showNewPwdForm = (currentSecret) => {
    clearNode(host);
    const newIn = el('input', { type: 'password', class: 'input ltr-value', autocomplete: 'off', required: true, minlength: 12 });
    const confIn = el('input', { type: 'password', class: 'input ltr-value', autocomplete: 'off', required: true });
    const submitBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, t(lang, 'save'));

    const form = el(
      'form',
      {
        onSubmit: async (e) => {
          e.preventDefault();
          errBox.classList.add('hidden');
          if (newIn.value !== confIn.value) {
            errBox.textContent = t(lang, 'passwordsMismatch');
            errBox.classList.remove('hidden');
            return;
          }
          submitBtn.disabled = true;
          try {
            if (session.unlockMethod === 'password') {
              await session.changeMasterPassword({
                currentPassword: currentSecret,
                newMasterPassword: newIn.value,
              });
            } else {
              await session.setSecondaryUnlock({
                currentSecret,
                altSecret: newIn.value,
              });
            }
            newIn.value = '';
            confIn.value = '';
            sheet.close();
            showToast(`${t(lang, 'save')} ✓`, 'success');
            onDone && (await onDone());
          } catch (err) {
            errBox.textContent = formatError(err, lang);
            errBox.classList.remove('hidden');
            submitBtn.disabled = false;
          }
        },
      },
      errBox,
      el('div', { class: 'field' }, el('label', { class: 'field-label' }, lang === 'en' ? 'New Master Password (12+ chars)' : 'كلمة المرور الرئيسية الجديدة (١٢ حرفاً+)'), newIn),
      el('div', { class: 'field' }, el('label', { class: 'field-label' }, t(lang, 'confirmPasswordLabel')), confIn),
      submitBtn
    );
    host.appendChild(form);
  };

  host.appendChild(
    renderCurrentLockStep({
      session,
      lang,
      submitLabel: t(lang, 'confirmBtn'),
      onVerified: async (secret) => {
        await session.verifyReauth({ masterPassword: secret });
        showNewPwdForm(secret);
      },
    })
  );

  const sheet = openBottomSheet({
    title: session.hasPasswordUnlock ? t(lang, 'changeMasterPwd') : t(lang, 'addOptionalPasswordBtn'),
    content: host,
  });
}

function openRotateRecoverySheet({ session, lang }) {
  const host = el('div', { class: 'settings-group' });

  host.appendChild(
    renderCurrentLockStep({
      session,
      lang,
      submitLabel: t(lang, 'rotateRecoveryKey'),
      onVerified: async (secret) => {
        const { recoveryKeyFormatted } = await session.rotateRecoveryKeyWithPassword(secret);
        clearNode(host);
        host.appendChild(el('div', { class: 'banner banner-warn' }, el('span', null, t(lang, 'recoveryModalWarn'))));
        host.appendChild(el('div', { class: 'recovery-key-display' }, recoveryKeyFormatted));
        host.appendChild(
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-primary btn-block',
              onClick: async () => {
                try {
                  await session.clipboard.copySecret(recoveryKeyFormatted, 0);
                  showToast(t(lang, 'copiedToast'), 'success');
                } catch (err) {
                  showToast(formatError(err, lang), 'warn');
                }
              },
            },
            svgIcon('copy', 16),
            t(lang, 'copyRecoveryKey')
          )
        );
      },
    })
  );

  openBottomSheet({ title: t(lang, 'rotateRecoveryKey'), content: host });
}

function openWipeVaultSheet({ session, lang }) {
  const confirmIn = el('input', {
    type: 'text',
    class: 'input ltr-value',
    autocomplete: 'off',
    placeholder: 'WIPE',
  });
  const btn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-danger btn-block',
      disabled: true,
      onClick: async () => {
        const ok = await requestReauth({ session, lang });
        if (!ok) return;
        await session.wipeVault();
        sheet.close();
        showToast(t(lang, 'wipeVaultBtn'), 'warn');
      },
    },
    t(lang, 'wipeVaultBtn')
  );

  confirmIn.addEventListener('input', () => {
    btn.disabled = confirmIn.value.trim().toUpperCase() !== 'WIPE';
  });

  const content = el(
    'div',
    { class: 'settings-group' },
    el('div', { class: 'banner banner-danger' }, el('span', null, t(lang, 'wipeVaultWarn'))),
    el('div', { class: 'field' }, el('label', { class: 'field-label' }, lang === 'en' ? 'Type WIPE to confirm' : 'اكتب WIPE للتأكيد'), confirmIn),
    btn
  );

  const sheet = openBottomSheet({ title: t(lang, 'wipeVaultBtn'), content });
}
