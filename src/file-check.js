/**
 * Khazna (خزنة) — Friendly Local File-Protocol Guard
 *
 * Browsers block ES Modules (<script type="module">), Service Workers, and
 * WebAuthn when index.html is opened directly via `file://`.
 * Because this classic script runs under strict CSP (`script-src 'self'`) even
 * on `file://`, it explains the 1-click fix (`start-khazna.bat`) instead of
 * leaving the user with an empty dark background.
 *
 * On `http://` or `https://`, this script returns immediately with zero work.
 */
(function () {
  'use strict';
  if (window.location.protocol !== 'file:') return;

  function renderFileNotice() {
    var root = document.getElementById('app');
    if (!root || root.childNodes.length > 0) return;

    function h(tag, cls, text) {
      var node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text !== undefined) node.textContent = text;
      return node;
    }

    var wrap = h('main', 'auth-shell');
    var card = h('section', 'glass-card auth-card');

    var hero = h('div', 'auth-hero');
    hero.appendChild(h('h1', 'auth-title', 'شغّل «خزنة» عبر الخادم المحلي (بدون إنترنت)'));
    hero.appendChild(
      h(
        'p',
        'auth-subtitle',
        'متصفح Chrome يمنع تشغيل وحدات التشفير (ES Modules و WebCrypto) عند فتح ملف index.html مباشرةً عبر file://.'
      )
    );
    card.appendChild(hero);

    var banner = h('div', 'banner banner-info');
    banner.appendChild(
      h(
        'span',
        '',
        'الحل بضغطة واحدة على ويندوز: افتح نفس المجلد واضغط مرتين على ملف start-khazna.bat — سيفتح التطبيق فوراً على http://localhost:8765 محلياً ١٠٠٪ بدون أي إنترنت أو تثبيت برامج.'
      )
    );
    card.appendChild(banner);

    var steps = h('div', 'settings-group');
    steps.appendChild(
      h('p', 'field-hint', '١) في نفس المجلد (بجانب index.html) اضغط مرتين على: start-khazna.bat')
    );
    steps.appendChild(
      h('p', 'field-hint', '٢) على Mac أو Linux شغّل: ./start-khazna.sh أو python3 -m http.server 8765')
    );
    steps.appendChild(
      h(
        'p',
        'field-hint',
        '٣) وللعمل على الهاتف (Android PWA + البصمة): ارفع محتوى المجلد على GitHub Pages أو Cloudflare Pages أو Netlify Drop ليحصل على رابط HTTPS.'
      )
    );
    steps.appendChild(
      h(
        'p',
        'field-hint ltr-value',
        'Opened via file:// — double-click start-khazna.bat (Windows) or run ./start-khazna.sh to open Khazna on http://localhost:8765.'
      )
    );
    card.appendChild(steps);

    wrap.appendChild(card);
    root.appendChild(wrap);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderFileNotice);
  } else {
    renderFileNotice();
  }
})();
