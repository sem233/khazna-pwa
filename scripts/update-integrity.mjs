import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

const FILES = [
  'index.html',
  'manifest.webmanifest',
  'sw.js',
  '_headers',
  'styles/theme.css',
  'styles/components.css',
  'styles/animations.css',
  'icons/icon.svg',
  'icons/icon-maskable.svg',
  'icons/pwa-192x192.png',
  'icons/pwa-512x512.png',
  'icons/pwa-maskable-512x512.png',
  'icons/apple-touch-icon.png',
  'src/file-check.js',
  'src/main.js',
  'src/i18n/strings.js',
  'src/crypto/utils.js',
  'src/crypto/argon2id-pure.js',
  'src/crypto/kdf.js',
  'src/crypto/kdf-worker.js',
  'src/crypto/vault-crypto.js',
  'src/storage/idb.js',
  'src/auth/webauthn.js',
  'src/auth/session.js',
  'src/domain/cards.js',
  'src/domain/search.js',
  'src/domain/audit.js',
  'src/import-export/csv.js',
  'src/import-export/spass.js',
  'src/import-export/formats.js',
  'src/import-export/manager.js',
  'src/import-export/sync.js',
  'src/ui/dom.js',
  'src/ui/unlock-view.js',
  'src/ui/generator-sheet.js',
  'src/ui/passwords-view.js',
  'src/ui/cards-view.js',
  'src/ui/notes-view.js',
  'src/ui/stats-view.js',
  'src/ui/import-export-sheet.js',
  'src/ui/sync-sheet.js',
  'src/ui/settings-view.js',
  'vendor/argon2.esm.js',
];

const fileHashes = {};
const shellParts = [];

for (const rel of FILES) {
  const fullPath = path.join(ROOT, rel);
  if (fs.existsSync(fullPath)) {
    const content = fs.readFileSync(fullPath);
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    fileHashes[rel] = hash;
    if (['index.html', 'styles/theme.css', 'styles/components.css', 'manifest.webmanifest'].includes(rel)) {
      shellParts.push(content.toString('utf8'));
    }
  }
}

const shellSha256 = crypto.createHash('sha256').update(shellParts.join('\n')).digest('hex');

const integrityData = {
  version: '2.0.0',
  generatedAt: new Date().toISOString(),
  algorithm: 'SHA-256',
  shellSha256,
  fileCount: Object.keys(fileHashes).length,
  files: fileHashes,
};

fs.writeFileSync(
  path.join(ROOT, 'app-integrity.json'),
  JSON.stringify(integrityData, null, 2) + '\n',
  'utf8'
);

console.log(`Updated app-integrity.json (v2.0.0) with ${Object.keys(fileHashes).length} files.`);
console.log(`Shell SHA-256: ${shellSha256}`);
