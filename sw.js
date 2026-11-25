/**
 * Khazna (خزنة) Offline-First Service Worker
 *
 * SECURITY GUARANTEES:
 * 1. Strict same-origin only — NEVER caches or proxies external origins.
 * 2. NEVER silently replaces code on update: waits in 'installed' state until the user
 *    explicitly confirms activation via `{ type: 'KHAZNA_SKIP_WAITING' }`.
 * 3. Full offline usability after first load (cache-first for app shell).
 */

const CACHE_NAME = 'khazna-shell-v2.4.0';

const APP_SHELL_ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './app-integrity.json',
  './styles/theme.css',
  './styles/components.css',
  './styles/animations.css',
  './icons/icon.svg',
  './icons/icon-maskable.svg',
  './icons/pwa-192x192.png',
  './icons/pwa-512x512.png',
  './icons/pwa-maskable-512x512.png',
  './icons/apple-touch-icon.png',
  './src/file-check.js',
  './src/main.js',
  './src/i18n/strings.js',
  './src/crypto/utils.js',
  './src/crypto/argon2id-pure.js',
  './src/crypto/kdf.js',
  './src/crypto/kdf-worker.js',
  './src/crypto/vault-crypto.js',
  './src/storage/idb.js',
  './src/auth/webauthn.js',
  './src/auth/session.js',
  './src/domain/cards.js',
  './src/domain/search.js',
  './src/domain/audit.js',
  './src/import-export/csv.js',
  './src/import-export/spass.js',
  './src/import-export/formats.js',
  './src/import-export/manager.js',
  './src/import-export/sync.js',
  './src/ui/dom.js',
  './src/ui/pattern-pad.js',
  './src/ui/unlock-view.js',
  './src/ui/generator-sheet.js',
  './src/ui/passwords-view.js',
  './src/ui/cards-view.js',
  './src/ui/notes-view.js',
  './src/ui/stats-view.js',
  './src/ui/import-export-sheet.js',
  './src/ui/sync-sheet.js',
  './src/ui/settings-view.js',
  './vendor/argon2.esm.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      // Cache each asset resiliently so optional files never abort offline installation
      await Promise.allSettled(
        APP_SHELL_ASSETS.map((url) =>
          fetch(url, { cache: 'reload' }).then((res) => {
            if (res.ok) return cache.put(url, res);
          })
        )
      );
    })
  );
  // Intentionally do NOT call self.skipWaiting() here!
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k.startsWith('khazna-shell-') && k !== CACHE_NAME)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'KHAZNA_SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Enforce strict same-origin isolation
  if (url.origin !== self.location.origin) {
    return;
  }

  event.respondWith(
    caches.match(req, { ignoreSearch: req.mode === 'navigate' }).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((networkRes) => {
        if (networkRes && networkRes.ok && networkRes.type === 'basic') {
          const clone = networkRes.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
        }
        return networkRes;
      }).catch(() => {
        if (req.mode === 'navigate') {
          return caches.match('./index.html');
        }
        return new Response('Offline', { status: 503, statusText: 'Offline' });
      });
    })
  );
});
