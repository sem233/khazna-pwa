/**
 * Khazna (خزنة) — Clean PC & Standalone Release Builder
 *
 * Produces:
 * 1) `dist/pc/`:
 *    - `index.html`: Clean, elegant entrypoint.
 *    - `khazna.bundle.css`: All CSS compiled into one file.
 *    - `khazna.bundle.js`: All JavaScript bundled with esbuild (IIFE, no imports across files).
 *    Works instantly by double-clicking index.html in any browser (file://) or over any static host!
 * 2) `dist/khazna-single.html`:
 *    - 100% single-file self-contained version with lenient meta CSP allowing offline local execution.
 */

import { execSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

async function buildStandalone() {
  console.log('⚡ Bundling JavaScript with npx esbuild...');

  const distDir = path.join(ROOT, 'dist');
  const pcDir = path.join(distDir, 'pc');
  await fs.mkdir(pcDir, { recursive: true });

  const tempBundlePath = path.join(pcDir, 'khazna.bundle.js');
  const entryPoint = path.join(ROOT, 'src', 'main.js');

  execSync(
    `npx esbuild "${entryPoint}" --bundle --format=iife --target=es2022,chrome109,edge109,firefox115 --outfile="${tempBundlePath}"`,
    { stdio: 'inherit' }
  );

  const bundledJs = await fs.readFile(tempBundlePath, 'utf8');
  console.log(`✓ JavaScript bundled: ${(bundledJs.length / 1024).toFixed(1)} KB`);

  // Read CSS files
  const themeCss = await fs.readFile(path.join(ROOT, 'styles', 'theme.css'), 'utf8');
  const componentsCss = await fs.readFile(path.join(ROOT, 'styles', 'components.css'), 'utf8');
  const animationsCss = await fs.readFile(path.join(ROOT, 'styles', 'animations.css'), 'utf8');
  const combinedCss = `${themeCss}\n\n${componentsCss}\n\n${animationsCss}`;

  const cssPath = path.join(pcDir, 'khazna.bundle.css');
  await fs.writeFile(cssPath, combinedCss, 'utf8');
  console.log(`✓ CSS bundled: ${(combinedCss.length / 1024).toFixed(1)} KB`);

  // Read template HTML
  const indexHtml = await fs.readFile(path.join(ROOT, 'index.html'), 'utf8');

  // Extract body markup (excluding external script tags and file-check.js)
  const bodyContentMatch = indexHtml.match(/<body>([\s\S]*?)<\/body>/i);
  if (!bodyContentMatch) throw new Error('Could not parse body from index.html');

  let bodyContent = bodyContentMatch[1];
  bodyContent = bodyContent.replace(/<script[^>]*src=["']\.\/src\/[^"']+["'][^>]*><\/script>/gi, '');

  // 1) PC 2-file / 3-file clean distribution (index.html + khazna.bundle.css + khazna.bundle.js)
  const pcHtml = `<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
    <meta name="referrer" content="no-referrer" />
    <meta name="theme-color" content="#070b14" />
    <title>خزنة (Khazna) — مدير كلمات مرور محلي</title>
    <link rel="stylesheet" href="./khazna.bundle.css" />
  </head>
  <body>
${bodyContent.trim()}
    <script src="./khazna.bundle.js"></script>
  </body>
</html>`;

  await fs.writeFile(path.join(pcDir, 'index.html'), pcHtml, 'utf8');
  console.log(`✓ Clean PC distribution created in: ${pcDir}`);

  // 2) Single-File standalone version (with meta CSP allowing inline)
  const singleHtml = `<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src 'self'; connect-src 'self';"
    />
    <meta name="referrer" content="no-referrer" />
    <meta name="theme-color" content="#070b14" />
    <title>خزنة (Khazna) — مدير كلمات مرور محلي</title>
    <style>
${combinedCss}
    </style>
  </head>
  <body>
${bodyContent.trim()}
    <script>
${bundledJs}
    </script>
  </body>
</html>`;

  await fs.writeFile(path.join(distDir, 'khazna.html'), singleHtml, 'utf8');
  console.log(`✓ Standalone single-file created: ${path.join(distDir, 'khazna.html')}`);
}

buildStandalone().catch((err) => {
  console.error('Build error:', err);
  process.exit(1);
});
