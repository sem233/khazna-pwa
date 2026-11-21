import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT, 'dist');

if (!fs.existsSync(DIST_DIR)) {
  fs.mkdirSync(DIST_DIR, { recursive: true });
}

console.log('Building release ZIP archives...');

// 1. Chrome Extension ZIP
const extDir = path.join(ROOT, 'chrome-extension');
const extZip = path.join(DIST_DIR, 'khazna-chrome-extension-v2.0.0.zip');
if (fs.existsSync(extZip)) fs.unlinkSync(extZip);

// 2. PC Web Direct Release ZIP
const pcZip = path.join(DIST_DIR, 'khazna-pc-web-v2.0.0.zip');
if (fs.existsSync(pcZip)) fs.unlinkSync(pcZip);

// Also update root khazna-pwa.zip (used by in-app download button)
const rootPwaZip = path.join(ROOT, 'khazna-pwa.zip');
if (fs.existsSync(rootPwaZip)) fs.unlinkSync(rootPwaZip);

try {
  // Compress chrome-extension
  execSync(
    `powershell -Command "Compress-Archive -Path '${extDir}\\*' -DestinationPath '${extZip}' -Force"`,
    { stdio: 'inherit' }
  );
  console.log(`✓ Created ${extZip}`);

  // Files to include in PC Web release
  const webFiles = [
    'index.html',
    'manifest.webmanifest',
    'sw.js',
    '_headers',
    'app-integrity.json',
    'local-server.mjs',
    'start-khazna.bat',
    'start-khazna.sh',
    'README.md',
    'SECURITY.md',
    'styles',
    'icons',
    'src',
    'vendor',
  ];

  const sourcePaths = webFiles.map(f => `'${path.join(ROOT, f)}'`).join(',');
  execSync(
    `powershell -Command "Compress-Archive -Path ${sourcePaths} -DestinationPath '${pcZip}' -Force"`,
    { stdio: 'inherit' }
  );
  console.log(`✓ Created ${pcZip}`);

  // Copy to root khazna-pwa.zip for in-app download button
  fs.copyFileSync(pcZip, rootPwaZip);
  console.log(`✓ Updated root ${rootPwaZip}`);

} catch (err) {
  console.error('Error creating zip archives:', err);
  process.exit(1);
}

console.log('All release archives built successfully!');
