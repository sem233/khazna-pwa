import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT, 'dist');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const VERSION = pkg.version || '2.2.0';

if (!fs.existsSync(DIST_DIR)) {
  fs.mkdirSync(DIST_DIR, { recursive: true });
}

console.log(`Building release ZIP archives for v${VERSION}...`);

// Ensure standalone PC + Chrome Extension bundles are freshly built first
execSync('node scripts/build-standalone-pc.mjs', { cwd: ROOT, stdio: 'inherit' });

const extDir = path.join(ROOT, 'chrome-extension');
const extZip = path.join(DIST_DIR, `khazna-chrome-extension-v${VERSION}.zip`);
const pcStandaloneDir = path.join(DIST_DIR, 'pc');
const pcStandaloneZip = path.join(DIST_DIR, `khazna-pc-standalone-v${VERSION}.zip`);
const pcZip = path.join(DIST_DIR, `khazna-pc-web-v${VERSION}.zip`);
const rootPwaZip = path.join(ROOT, 'khazna-pwa.zip');

for (const f of [extZip, pcStandaloneZip, pcZip, rootPwaZip]) {
  if (fs.existsSync(f)) fs.unlinkSync(f);
}

try {
  execSync(
    `powershell -Command "Compress-Archive -Path '${extDir}\\*' -DestinationPath '${extZip}' -Force"`,
    { stdio: 'inherit' }
  );
  console.log(`✓ Created ${extZip}`);

  execSync(
    `powershell -Command "Compress-Archive -Path '${pcStandaloneDir}\\*' -DestinationPath '${pcStandaloneZip}' -Force"`,
    { stdio: 'inherit' }
  );
  console.log(`✓ Created ${pcStandaloneZip}`);

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
    'package.json',
  ];

  const sourcePaths = webFiles.map((f) => `'${path.join(ROOT, f)}'`).join(',');
  execSync(
    `powershell -Command "Compress-Archive -Path ${sourcePaths} -DestinationPath '${pcZip}' -Force"`,
    { stdio: 'inherit' }
  );
  console.log(`✓ Created ${pcZip}`);

  fs.copyFileSync(pcZip, rootPwaZip);
  console.log(`✓ Updated root ${rootPwaZip}`);
} catch (err) {
  console.error('Error creating zip archives:', err);
  process.exit(1);
}

console.log('All release archives built successfully!');
