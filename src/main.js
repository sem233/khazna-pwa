/**
 * Khazna (خزنة) — Application Bootstrap, Navigation, PWA Lifecycle & Privacy Blur
 */

import { VaultSession } from './auth/session.js';
import { sha256Hex } from './crypto/utils.js';
import { t } from './i18n/strings.js';
import { extractSyncTokenFromInput, SYNC_PREFIX } from './import-export/sync.js';
import { VaultStorage } from './storage/idb.js';
import { openCardEditorSheet, renderCardsView } from './ui/cards-view.js';
import { clearNode, el, showToast, svgIcon, triggerHaptic } from './ui/dom.js';
import { openImportExportSheet } from './ui/import-export-sheet.js';
import { openNoteEditorSheet, renderNotesView } from './ui/notes-view.js';
import { openPasswordEditorSheet, renderPasswordsView } from './ui/passwords-view.js';
import { renderSettingsView } from './ui/settings-view.js';
import { renderStatsView } from './ui/stats-view.js';
import { openSyncSheet } from './ui/sync-sheet.js';
import { renderUnlockView } from './ui/unlock-view.js';

const APP_VERSION = '1.0.0';

const storage = new VaultStorage();
const session = new VaultSession({ storage });

const appState = {
  tab: 'passwords', // passwords | cards | notes | stats | settings
  pendingRecoveryKey: null,
  sections: [],
  passwords: [],
  trashedPasswords: [],
  cards: [],
  notes: [],
  snapshots: [],
  vaultSizeBytes: 0,
  storageStatus: { persisted: false, usageBytes: 0, quotaBytes: 0, percentUsed: 0 },
  integrityInfo: { version: APP_VERSION, shellSha256: '' },
  pwFilter: {
    query: '',
    sectionId: 'all',
    favoritesOnly: false,
    duplicatesOnly: false,
    showTrash: false,
    sortBy: 'updated-desc',
    selectedIds: new Set(),
  },
  notesQuery: '',
  twoStepCopy: null, // { title, password }
  isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true,
  pwa: {
    deferredPrompt: null,
    canInstall: false,
    isInstalled:
      window.matchMedia('(display-mode: standalone)').matches ||
      navigator.standalone === true,
    isIOS: /iphone|ipad|ipod/i.test(navigator.userAgent || ''),
    updateWaiting: null,
  },
  sharedImportText: '',
  pendingSyncCode: '',
};

function getLang() {
  return session.settings?.lang === 'en' ? 'en' : 'ar';
}

function applyThemeAndDirection() {
  const settings = session.settings || {};
  const lang = getLang();
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'en' ? 'ltr' : 'rtl';
  document.documentElement.dataset.theme = settings.theme || 'dark';

  // Auto-reduce heavy blur on low-end devices (<= 2 logical cores or <= 2 GB RAM)
  const lowEnd =
    (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2) ||
    (navigator.deviceMemory && navigator.deviceMemory <= 2);
  if (settings.lowEndBlur === 'reduced' || (settings.lowEndBlur === 'auto' && lowEnd)) {
    document.documentElement.dataset.blur = 'reduced';
  } else {
    delete document.documentElement.dataset.blur;
  }

  const themeColorMeta = document.querySelector('meta[name="theme-color"]');
  if (themeColorMeta) {
    const color = settings.theme === 'light' ? '#eef3fb' : (settings.theme === 'amoled' ? '#000000' : '#070b14');
    themeColorMeta.setAttribute('content', color);
  }

  const pTitle = document.getElementById('privacy-title');
  const pSub = document.getElementById('privacy-sub');
  if (pTitle) pTitle.textContent = t(lang, 'privacyOverlayTitle');
  if (pSub) pSub.textContent = t(lang, 'privacyOverlaySub');
}

async function computeRuntimeIntegrity() {
  try {
    const resp = await fetch('./app-integrity.json', { cache: 'no-store' });
    if (resp.ok) {
      const json = await resp.json();
      if (json?.shellSha256) {
        appState.integrityInfo = {
          version: json.version || APP_VERSION,
          shellSha256: json.shellSha256,
        };
        return;
      }
    }
  } catch {
    // Fallback to live SHA-256 of index.html + CSS + main.js
  }
  try {
    const files = ['./index.html', './styles/theme.css', './styles/components.css', './manifest.webmanifest'];
    const parts = [];
    for (const f of files) {
      const r = await fetch(f, { cache: 'no-store' });
      if (r.ok) parts.push(await r.text());
    }
    const hash = await sha256Hex(parts.join('\n'));
    appState.integrityInfo = { version: APP_VERSION, shellSha256: hash };
  } catch {
    appState.integrityInfo = { version: APP_VERSION, shellSha256: 'offline-local' };
  }
}

async function loadDecryptedVaultData() {
  if (!session.isUnlocked) return;
  const [sections, allPasswords, cards, notes, snapshots, allRaw] = await Promise.all([
    session.listRecords('section'),
    session.listRecords('password', { includeTrashed: true }),
    session.listRecords('card'),
    session.listRecords('note'),
    storage.listSnapshots(),
    storage.getAllRecords(),
  ]);

  appState.sections = sections.sort((a, b) => (a.data?.order ?? 0) - (b.data?.order ?? 0));
  appState.passwords = allPasswords.filter((p) => !p.deletedAt);
  appState.trashedPasswords = allPasswords.filter((p) => Boolean(p.deletedAt));
  appState.cards = cards;
  appState.notes = notes;
  appState.snapshots = snapshots;

  let bytes = JSON.stringify(session.header || {}).length;
  for (const r of allRaw) bytes += JSON.stringify(r).length;
  appState.vaultSizeBytes = bytes;
}

function withViewTransition(fn) {
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!reduced && typeof document.startViewTransition === 'function') {
    document.startViewTransition(fn);
  } else {
    fn();
  }
}

function renderApp({ preserveSearchFocus = false } = {}) {
  const root = document.getElementById('app');
  if (!root) return;
  const lang = getLang();

  let activeSearchPos = null;
  if (preserveSearchFocus && document.activeElement?.type === 'search') {
    activeSearchPos = document.activeElement.selectionStart;
  }

  clearNode(root);

  // --- Locked or Onboarding State ---
  if (!session.isUnlocked || appState.pendingRecoveryKey) {
    root.appendChild(
      renderUnlockView({
        session,
        lang,
        pendingRecoveryKey: appState.pendingRecoveryKey,
        hasPendingSync: Boolean(appState.pendingSyncCode),
        onDownloadZip: handleDownloadZip,
        onToggleLang: async () => {
          await session.updateSettings({ lang: lang === 'ar' ? 'en' : 'ar' });
          applyThemeAndDirection();
          renderApp();
        },
        onRecoveryConfirmed: async (newRecoveryKey) => {
          if (typeof newRecoveryKey === 'string') {
            appState.pendingRecoveryKey = newRecoveryKey;
            renderApp();
          } else {
            appState.pendingRecoveryKey = null;
            await loadDecryptedVaultData();
            withViewTransition(() => renderApp());
          }
        },
      })
    );
    return;
  }

  // --- Unlocked App Shell ---
  const header = el(
    'header',
    { class: 'app-header' },
    el(
      'div',
      { class: 'header-inner' },
      el(
        'div',
        { class: 'brand-mark' },
        el('div', { class: 'brand-logo', 'aria-hidden': 'true' }, svgIcon('shield', 18)),
        el('h1', { class: 'brand-title' }, t(lang, 'appName'))
      ),
      el(
        'div',
        { class: 'header-actions' },
        // Install button moved to Settings view only
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm',
            'aria-label': t(lang, 'syncTitle'),
            'data-testid': 'header-sync-btn',
            onClick: () => openDeviceSync('send'),
          },
          svgIcon('link', 15),
          t(lang, 'syncBtnShort')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm',
            'aria-label': t(lang, 'lockNow'),
            onClick: () => {
              appState.twoStepCopy = null;
              session.lock({ reason: 'manual' });
            },
          },
          svgIcon('lock', 16),
          t(lang, 'lockNow')
        )
      )
    )
  );

  const mainShell = el('main', { class: 'app-shell' });

  // Offline indicator
  if (!appState.isOnline) {
    mainShell.appendChild(el('div', { class: 'banner banner-info' }, el('span', null, t(lang, 'offlineBadge'))));
  }

  // SW manual update confirmation banner (never silent replacement)
  if (appState.pwa.updateWaiting) {
    mainShell.appendChild(
      el(
        'div',
        { class: 'banner banner-info' },
        el('span', null, t(lang, 'updateAvailable')),
        el('button', { type: 'button', class: 'btn btn-sm btn-primary', onClick: activateWaitingUpdate }, t(lang, 'updateConfirmBtn'))
      )
    );
  }

  if (appState.tab === 'passwords') {
    mainShell.appendChild(
      renderPasswordsView({
        session,
        lang,
        sections: appState.sections,
        passwords: appState.passwords,
        trashedPasswords: appState.trashedPasswords,
        state: appState.pwFilter,
        onStateChange: (patch, opts = {}) => {
          appState.pwFilter = { ...appState.pwFilter, ...patch };
          renderApp({ preserveSearchFocus: Boolean(opts.keepFocus) });
        },
        onRefresh: refreshAndRender,
        onShowTwoStepBar: (info) => {
          appState.twoStepCopy = info;
          renderApp();
        },
      })
    );
  } else if (appState.tab === 'cards') {
    mainShell.appendChild(
      renderCardsView({
        session,
        lang,
        cards: appState.cards,
        onRefresh: refreshAndRender,
      })
    );
  } else if (appState.tab === 'notes') {
    mainShell.appendChild(
      renderNotesView({
        session,
        lang,
        notes: appState.notes,
        query: appState.notesQuery,
        onQueryChange: (q) => {
          appState.notesQuery = q;
          renderApp({ preserveSearchFocus: true });
        },
        onRefresh: refreshAndRender,
      })
    );
  } else if (appState.tab === 'stats') {
    mainShell.appendChild(
      renderStatsView({
        session,
        lang,
        sections: appState.sections,
        passwords: appState.passwords,
        cards: appState.cards,
        notes: appState.notes,
        vaultSizeBytes: appState.vaultSizeBytes,
        onOpenSection: (sectionId) => {
          appState.pwFilter = {
            ...appState.pwFilter,
            sectionId,
            showTrash: false,
            favoritesOnly: false,
            duplicatesOnly: false,
          };
          appState.tab = 'passwords';
          withViewTransition(() => renderApp());
        },
        onOpenBackup: () =>
          openImportExportSheet({
            session,
            lang,
            sections: appState.sections,
            passwords: appState.passwords,
            cards: appState.cards,
            notes: appState.notes,
            initialTab: 'export',
            onChanged: refreshAndRender,
          }),
      })
    );
  } else if (appState.tab === 'settings') {
    mainShell.appendChild(
      renderSettingsView({
        session,
        lang,
        storageStatus: appState.storageStatus,
        integrityInfo: appState.integrityInfo,
        snapshots: appState.snapshots,
        pwaState: appState.pwa,
        onOpenImportExport: () =>
          openImportExportSheet({
            session,
            lang,
            sections: appState.sections,
            passwords: appState.passwords,
            cards: appState.cards,
            notes: appState.notes,
            initialTab: 'import',
            onChanged: refreshAndRender,
          }),
        onOpenSync: () => openDeviceSync('send'),
        onDownloadZip: handleDownloadZip,
        onRefresh: refreshAndRender,
        onApplySettings: () => {
          applyThemeAndDirection();
          renderApp();
        },
        onActivateUpdate: activateWaitingUpdate,
        onInstallPwa: handleInstallPwa,
      })
    );
  }

  // --- Floating Two-Step Copy Mini-Bar ---
  let miniBar = null;
  if (appState.twoStepCopy) {
    const { title, password } = appState.twoStepCopy;
    miniBar = el(
      'div',
      { class: 'mini-copy-bar', role: 'region', 'aria-label': t(lang, 'copyCombo') },
      el('span', null, `${title}: ${t(lang, 'twoStepNextPass')}`),
      el(
        'div',
        { class: 'toolbar-row' },
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-primary',
            onClick: async () => {
              await session.clipboard.copySecret(password, session.settings?.clipboardClearSec ?? 30);
              triggerHaptic();
              showToast(`${t(lang, 'copiedToast')}: ${t(lang, 'passwordLabel')}`, 'success');
              appState.twoStepCopy = null;
              renderApp();
            },
          },
          svgIcon('copy', 15),
          t(lang, 'copyPassNow')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-icon btn-sm btn-ghost',
            'aria-label': t(lang, 'close'),
            onClick: () => {
              appState.twoStepCopy = null;
              renderApp();
            },
          },
          svgIcon('close', 16)
        )
      )
    );
  }

  // --- Floating Action Button (FAB) on Passwords / Cards / Notes tabs ---
  let fab = null;
  if (appState.tab === 'passwords' || appState.tab === 'cards' || appState.tab === 'notes') {
    const fabLabel =
      appState.tab === 'passwords'
        ? t(lang, 'addEntry')
        : appState.tab === 'cards'
          ? t(lang, 'addCard')
          : t(lang, 'addNote');

    fab = el(
      'button',
      {
        type: 'button',
        class: 'fab-btn',
        'aria-label': fabLabel,
        title: fabLabel,
        onClick: () => {
          triggerHaptic(14);
          if (appState.tab === 'passwords') {
            openPasswordEditorSheet({
              session,
              lang,
              sections: appState.sections,
              defaultSectionId: appState.pwFilter.sectionId !== 'all' ? appState.pwFilter.sectionId : null,
              onSaved: refreshAndRender,
            });
          } else if (appState.tab === 'cards') {
            openCardEditorSheet({ session, lang, onSaved: refreshAndRender });
          } else {
            openNoteEditorSheet({ session, lang, onSaved: refreshAndRender });
          }
        },
      },
      svgIcon('plus', 24)
    );
  }

  // --- Bottom Navigation Bar (5 Tabs) ---
  const navItems = [
    { id: 'passwords', icon: 'key', label: t(lang, 'navPasswords') },
    { id: 'cards', icon: 'card', label: t(lang, 'navCards') },
    { id: 'notes', icon: 'note', label: t(lang, 'navNotes') },
    { id: 'stats', icon: 'chart', label: t(lang, 'navStats') },
    { id: 'settings', icon: 'settings', label: t(lang, 'navSettings') },
  ];

  const bottomNav = el(
    'nav',
    { class: 'bottom-nav', 'aria-label': 'Navigation' },
    el(
      'div',
      { class: 'bottom-nav-inner' },
      ...navItems.map((item) =>
        el(
          'button',
          {
            type: 'button',
            class: `nav-item ${appState.tab === item.id ? 'is-active' : ''}`.trim(),
            'aria-current': appState.tab === item.id ? 'page' : undefined,
            onClick: () => {
              if (appState.tab === item.id) return;
              appState.tab = item.id;
              appState.twoStepCopy = null;
              withViewTransition(() => renderApp());
            },
          },
          svgIcon(item.icon, 20),
          el('span', null, item.label)
        )
      )
    )
  );

  root.appendChild(header);
  root.appendChild(mainShell);
  if (miniBar) root.appendChild(miniBar);
  if (fab) root.appendChild(fab);
  root.appendChild(bottomNav);

  if (preserveSearchFocus) {
    const searchEl = root.querySelector('input[type="search"]');
    if (searchEl) {
      searchEl.focus();
      if (activeSearchPos !== null) {
        try {
          searchEl.setSelectionRange(activeSearchPos, activeSearchPos);
        } catch {
          // ignore
        }
      }
    }
  }

  // Auto-open Device Sync modal immediately after unlock if opened from a `#sync=...` link
  if (appState.pendingSyncCode) {
    const code = appState.pendingSyncCode;
    appState.pendingSyncCode = '';
    openDeviceSync('receive', code);
  }

  // Open share-target import automatically after unlock if text was shared via Android Share Sheet
  if (appState.sharedImportText) {
    const shared = appState.sharedImportText;
    appState.sharedImportText = '';
    openImportExportSheet({
      session,
      lang,
      sections: appState.sections,
      passwords: appState.passwords,
      cards: appState.cards,
      notes: appState.notes,
      initialTab: 'import',
      initialPastedText: shared,
      onChanged: refreshAndRender,
    });
  }
}

async function refreshAndRender() {
  await loadDecryptedVaultData();
  renderApp();
}

function openDeviceSync(initialTab = 'send', initialSyncCode = '') {
  openSyncSheet({
    session,
    lang: getLang(),
    sections: appState.sections,
    passwords: appState.passwords,
    cards: appState.cards,
    notes: appState.notes,
    initialTab,
    initialSyncCode,
    onSynced: refreshAndRender,
  });
}

async function handleDownloadZip() {
  const lang = getLang();
  try {
    const resp = await fetch('./khazna-pwa.zip', { cache: 'no-store' });
    if (!resp.ok) throw new Error('ZIP unavailable');
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'khazna-pwa.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    showToast(t(lang, 'downloadZipToast'), 'success');
  } catch {
    showToast(lang === 'en' ? 'Could not download khazna-pwa.zip' : 'تعذّر تنزيل ملف khazna-pwa.zip', 'error');
  }
}

function captureIncomingSyncHash() {
  const hash = window.location.hash || '';
  if (!hash || !hash.includes('sync=')) return false;
  const token = extractSyncTokenFromInput(hash);
  if (!token) return false;
  appState.pendingSyncCode = `${SYNC_PREFIX}${token}`;
  // Immediately scrub `#sync=...` from browser URL bar & history
  try {
    window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`);
  } catch {
    // ignore
  }
  return true;
}

// --- PWA Install & User-Gated Service Worker Updates ---

async function handleInstallPwa() {
  const promptEvt = appState.pwa.deferredPrompt;
  if (!promptEvt) return;
  await promptEvt.prompt();
  const choice = await promptEvt.userChoice;
  if (choice?.outcome === 'accepted') {
    appState.pwa.isInstalled = true;
    appState.pwa.canInstall = false;
    appState.pwa.deferredPrompt = null;
    renderApp();
  }
}

function activateWaitingUpdate() {
  const waiting = appState.pwa.updateWaiting;
  if (!waiting) return;
  waiting.postMessage({ type: 'KHAZNA_SKIP_WAITING' });
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', async () => {
    try {
      const reg = await navigator.serviceWorker.register('./sw.js', { scope: './' });

      if (reg.waiting) {
        appState.pwa.updateWaiting = reg.waiting;
        renderApp();
      }

      reg.addEventListener('updatefound', () => {
        const nextWorker = reg.installing;
        if (!nextWorker) return;
        nextWorker.addEventListener('statechange', () => {
          if (nextWorker.state === 'installed' && navigator.serviceWorker.controller) {
            // Never silently replace code — wait for explicit user confirmation!
            appState.pwa.updateWaiting = nextWorker;
            renderApp();
          }
        });
      });

      let reloading = false;
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        if (reloading) return;
        reloading = true;
        window.location.reload();
      });
    } catch {
      // Service worker registration may fail on non-HTTPS origins; app continues normally.
    }
  });
}

// --- Global Listeners: Privacy Blur, Auto-Lock Activity, Clipboard Status, Online/Offline, Install ---

function wireGlobalEvents() {
  session.on(async (evt) => {
    if (evt.type === 'unlocked') {
      await loadDecryptedVaultData();
      if (!appState.pendingRecoveryKey && evt.method !== 'create') {
        withViewTransition(() => renderApp());
      }
    } else if (evt.type === 'locked' || evt.type === 'wiped') {
      appState.sections = [];
      appState.passwords = [];
      appState.trashedPasswords = [];
      appState.cards = [];
      appState.notes = [];
      appState.twoStepCopy = null;
      const modalRoot = document.getElementById('modal-root');
      if (modalRoot) clearNode(modalRoot);
      renderApp();
    } else if (evt.type === 'privacy-blur') {
      const overlay = document.getElementById('privacy-overlay');
      if (overlay) {
        overlay.classList.toggle('hidden', !evt.blurred);
        overlay.setAttribute('aria-hidden', evt.blurred ? 'false' : 'true');
      }
    } else if (evt.type === 'sync-updated' && session.isUnlocked) {
      await loadDecryptedVaultData();
      renderApp();
    }
  });

  session.clipboard.onStatus((ev) => {
    if (ev.type === 'cleared') {
      showToast(t(getLang(), 'clipboardCleared'), 'info', 2200);
    }
  });

  document.addEventListener('visibilitychange', () => {
    session.handleVisibilityChange(document.hidden);
  });

  window.addEventListener('blur', () => {
    if (session.isUnlocked) session.setPrivacyBlur(true);
  });
  window.addEventListener('focus', () => {
    session.setPrivacyBlur(false);
    session.touchActivity();
  });

  const touch = () => session.touchActivity();
  window.addEventListener('pointerdown', touch, { passive: true });
  window.addEventListener('keydown', touch, { passive: true });

  window.addEventListener('online', () => {
    appState.isOnline = true;
    renderApp();
  });
  window.addEventListener('offline', () => {
    appState.isOnline = false;
    renderApp();
  });

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    appState.pwa.deferredPrompt = e;
    appState.pwa.canInstall = true;
    renderApp();
  });
  window.addEventListener('appinstalled', () => {
    appState.pwa.isInstalled = true;
    appState.pwa.canInstall = false;
    appState.pwa.deferredPrompt = null;
    renderApp();
  });
  window.addEventListener('hashchange', () => {
    if (captureIncomingSyncHash()) {
      if (session.isUnlocked && !appState.pendingRecoveryKey) {
        const code = appState.pendingSyncCode;
        appState.pendingSyncCode = '';
        openDeviceSync('receive', code);
      } else {
        renderApp();
      }
    }
  });
}

// --- Bootstrap ---

async function bootstrap() {
  wireGlobalEvents();
  captureIncomingSyncHash();
  await session.init();
  applyThemeAndDirection();

  // Check optional PWA share_target query parameter (?shared_text=...)
  const params = new URLSearchParams(window.location.search);
  const sharedText = params.get('text') || params.get('title') || '';
  if (sharedText) {
    appState.sharedImportText = sharedText;
    try {
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch {
      // ignore
    }
  }

  renderApp();

  // Non-blocking storage persistence & app-shell integrity check
  storage.requestPersistentStorage().then((st) => {
    appState.storageStatus = st;
    if (appState.tab === 'settings') renderApp();
  });
  computeRuntimeIntegrity().then(() => {
    if (appState.tab === 'settings') renderApp();
  });
  registerServiceWorker();
}

bootstrap();
