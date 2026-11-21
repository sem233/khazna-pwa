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

fs.mkdirSync(DIST_DIR, { recursive: true });

console.log(`Building clean PC package for v${VERSION}...`);
execSync('node scripts/build-standalone-pc.mjs', { cwd: ROOT, stdio: 'inherit' });

// Single clean PC archive containing ONLY khazna.html + chrome-extension/
const pcArchive = path.join(DIST_DIR, `khazna-pc-v${VERSION}.zip`);
if (fs.existsSync(pcArchive)) fs.unlinkSync(pcArchive);

const khaznaHtml = path.join(DIST_DIR, 'khazna.html');
const extDir = path.join(ROOT, 'chrome-extension');

execSync(
  `powershell -Command "Compress-Archive -Path '${khaznaHtml}','${extDir}' -DestinationPath '${pcArchive}' -Force"`,
  { stdio: 'inherit' }
);

console.log(`✓ Clean PC release package ready: ${pcArchive}`);
