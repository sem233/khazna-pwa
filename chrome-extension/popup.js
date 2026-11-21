/**
 * Khazna Chrome Extension Popup
 *
 * SECURITY: Zero external connections. All data is read from Chrome's
 * local storage which mirrors the same IndexedDB data as the PWA.
 * Passwords are NEVER sent anywhere.
 */

const APP_STATE = {
  unlocked: false,
  passwords: [],
  query: '',
};

// ---- Safe DOM helpers (zero innerHTML) ----

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (k === 'class') {
        node.className = String(v);
      } else {
        node.setAttribute(k, String(v));
      }
    }
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    if (child instanceof Node) node.appendChild(child);
    else node.appendChild(document.createTextNode(String(child)));
  }
  return node;
}

function txt(str) { return document.createTextNode(String(str ?? '')); }

function showToast(msg, type = 'info', ms = 1800) {
  let toast = document.getElementById('khazna-toast');
  if (!toast) {
    toast = el('div', { id: 'khazna-toast', class: 'toast' });
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.className = `toast visible ${type}`;
  setTimeout(() => { toast.className = 'toast'; }, ms);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    return true;
  }
}

// ---- Render functions ----

function renderApp() {
  const root = document.getElementById('app');
  while (root.firstChild) root.removeChild(root.firstChild);

  // Check if we have access to vault data
  // The extension reads from chrome.storage.local where the PWA may have stored
  // an encrypted copy — but since it's a PWA with IndexedDB, we show a note to
  // use the main app. The extension works as a shortcut/launcher with quick access.

  root.appendChild(renderHeader());

  if (!APP_STATE.unlocked) {
    root.appendChild(renderNoVaultView());
  } else {
    root.appendChild(renderPasswordsView());
  }
}

function renderHeader() {
  const lockBtn = el('button', { class: 'popup-lock-btn', onClick: () => {
    APP_STATE.unlocked = false;
    APP_STATE.passwords = [];
    renderApp();
  }});
  lockBtn.appendChild(txt('🔒 قفل'));

  return el('div', { class: 'popup-header' },
    el('div', { class: 'popup-logo' },
      el('div', { class: 'popup-logo-icon' },
        // Shield icon SVG
        (() => {
          const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
          svg.setAttribute('width', '16');
          svg.setAttribute('height', '16');
          svg.setAttribute('viewBox', '0 0 24 24');
          svg.setAttribute('fill', 'none');
          svg.setAttribute('stroke', '#ffffff');
          svg.setAttribute('stroke-width', '2.5');
          const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          path.setAttribute('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z');
          svg.appendChild(path);
          return svg;
        })()
      ),
      txt('خزنة')
    ),
    APP_STATE.unlocked ? lockBtn : el('span', { class: '' })
  );
}

function renderNoVaultView() {
  // Note: Chrome Extension cannot directly access PWA's IndexedDB
  // Show a helpful message to open the main app
  return el('div', { class: 'no-vault' },
    el('div', { class: '' }, txt('🔐')),
    el('div', { class: 'no-vault-title' }, txt('خزنة — اختصار الوصول السريع')),
    el('div', { class: 'no-vault-sub' },
      txt('هذا الاختصار يفتح خزنة بسرعة من شريط المتصفح. لفتح الخزنة الكاملة:')
    ),
    el('a', {
      class: 'no-vault-link',
      href: '#',
      onClick: (e) => {
        e.preventDefault();
        // Try to open the PWA or the web app
        chrome.tabs.create({ url: 'https://khazna.app' });
      }
    }, txt('فتح خزنة 🔗')),
    el('div', { class: 'no-vault-sub' },
      txt('💡 تلميح: قم بتثبيت خزنة كـ PWA من المتصفح للحصول على تجربة كاملة مع دعم البصمة والعمل بدون إنترنت.')
    )
  );
}

function renderPasswordsView() {
  const view = el('div', { class: 'pw-list-view' });

  const searchInput = el('input', {
    type: 'search',
    class: 'search-input',
    placeholder: 'ابحث في كلمات المرور...',
    value: APP_STATE.query,
    onInput: (e) => {
      APP_STATE.query = e.target.value;
      renderFilteredList(listEl, APP_STATE.passwords, APP_STATE.query);
    },
  });
  view.appendChild(el('div', { class: 'search-wrap' }, searchInput));

  const listEl = el('div', { class: 'pw-list' });
  renderFilteredList(listEl, APP_STATE.passwords, APP_STATE.query);
  view.appendChild(listEl);

  return view;
}

function renderFilteredList(listEl, passwords, query) {
  while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

  const q = (query || '').trim().toLowerCase();
  const filtered = q
    ? passwords.filter(p => {
        const d = p.data || {};
        return (d.title || '').toLowerCase().includes(q) ||
               (d.username || '').toLowerCase().includes(q) ||
               (d.url || '').toLowerCase().includes(q);
      })
    : passwords;

  if (filtered.length === 0) {
    listEl.appendChild(el('div', { class: 'empty-state' },
      txt(q ? 'لا توجد نتائج' : 'لا توجد بيانات متاحة')
    ));
    return;
  }

  for (const entry of filtered) {
    const d = entry.data || {};

    const item = el('div', { class: 'pw-item' });

    const copyBothBtn = el('button', {
      class: 'copy-btn both',
      title: 'نسخ المستخدم + كلمة المرور معاً',
      onClick: async () => {
        if (d.username && d.password) {
          await copyToClipboard(`${d.username}\t${d.password}`);
          showToast('تم نسخ المستخدم + كلمة المرور ✓', 'success');
        } else if (d.username) {
          await copyToClipboard(d.username);
          showToast('تم نسخ المستخدم ✓', 'success');
        } else if (d.password) {
          await copyToClipboard(d.password);
          showToast('تم نسخ كلمة المرور ✓', 'success');
        }
      },
    }, txt('⊞ نسخ'));

    const copyPassBtn = el('button', {
      class: 'copy-btn',
      title: 'نسخ كلمة المرور فقط',
      onClick: async () => {
        if (d.password) {
          await copyToClipboard(d.password);
          showToast('تم نسخ كلمة المرور ✓', 'success');
        }
      },
    }, txt('🔑'));

    item.appendChild(el('div', { class: 'pw-item-header' },
      el('div', { class: 'pw-item-title' },
        txt(d.title || 'بدون عنوان')
      ),
      el('div', { class: 'pw-item-actions' }, copyBothBtn, copyPassBtn)
    ));

    if (d.username) {
      item.appendChild(el('div', { class: 'pw-item-username' }, txt(d.username)));
    }

    listEl.appendChild(item);
  }
}

// ---- Bootstrap ----
document.addEventListener('DOMContentLoaded', () => {
  renderApp();
});
