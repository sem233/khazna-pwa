/**
 * Khazna (خزنة) — Clean PC Single-File & Chrome Extension Builder
 *
 * Produces ONLY:
 * 1) `dist/khazna.html`: Single self-contained HTML file for PC (double-click in any browser, zero server).
 * 2) `chrome-extension/`: Synced real offline vault bundle (popup.html, app.html, CSS, JS).
 */

import { execSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

async function buildStandalone() {
  console.log('⚡ Bundling JavaScript with npx esbuild...');

  const distDir = path.join(ROOT, 'dist');
  const extDir = path.join(ROOT, 'chrome-extension');
  await fs.mkdir(distDir, { recursive: true });
  await fs.mkdir(extDir, { recursive: true });

  const tempBundlePath = path.join(os.tmpdir(), `khazna-bundle-${Date.now()}.js`);
  const entryPoint = path.join(ROOT, 'src', 'main.js');

  execSync(
    `npx esbuild "${entryPoint}" --bundle --format=iife --target=es2022,chrome109,edge109,firefox115 --outfile="${tempBundlePath}"`,
    { stdio: 'inherit' }
  );

  const bundledJs = await fs.readFile(tempBundlePath, 'utf8');
  await fs.unlink(tempBundlePath).catch(() => {});
  console.log(`✓ JavaScript bundled: ${(bundledJs.length / 1024).toFixed(1)} KB`);

  // Read CSS files
  const themeCss = await fs.readFile(path.join(ROOT, 'styles', 'theme.css'), 'utf8');
  const componentsCss = await fs.readFile(path.join(ROOT, 'styles', 'components.css'), 'utf8');
  const animationsCss = await fs.readFile(path.join(ROOT, 'styles', 'animations.css'), 'utf8');
  const combinedCss = `${themeCss}\n\n${componentsCss}\n\n${animationsCss}`;
  console.log(`✓ CSS bundled: ${(combinedCss.length / 1024).toFixed(1)} KB`);

  // Read template HTML
  const indexHtml = await fs.readFile(path.join(ROOT, 'index.html'), 'utf8');
  const bodyContentMatch = indexHtml.match(/<body>([\s\S]*?)<\/body>/i);
  if (!bodyContentMatch) throw new Error('Could not parse body from index.html');

  let bodyContent = bodyContentMatch[1];
  bodyContent = bodyContent.replace(/<script[^>]*src=["']\.\/src\/[^"']+["'][^>]*><\/script>/gi, '');

  // 1) Single-File PC standalone version (double-click in browser, zero server)
  const singleHtml = `<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src 'self'; connect-src 'none';"
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
  console.log(`✓ PC single-file created: ${path.join(distDir, 'khazna.html')}`);

  // 2) Chrome Extension Manifest V3 real vault (strict CSP — external bundle files)
  await fs.writeFile(path.join(extDir, 'khazna.bundle.css'), combinedCss, 'utf8');
  await fs.writeFile(path.join(extDir, 'khazna.bundle.js'), bundledJs, 'utf8');

  const extPopupHtml = `<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark" data-chrome-popup="true">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>خزنة (Khazna)</title>
    <link rel="stylesheet" href="./khazna.bundle.css" />
  </head>
  <body>
${bodyContent.trim()}
    <script src="./khazna.bundle.js"></script>
  </body>
</html>`;

  const extFullHtml = `<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>خزنة (Khazna) — مدير كلمات المرور</title>
    <link rel="stylesheet" href="./khazna.bundle.css" />
  </head>
  <body>
${bodyContent.trim()}
    <script src="./khazna.bundle.js"></script>
  </body>
</html>`;

  await fs.writeFile(path.join(extDir, 'popup.html'), extPopupHtml, 'utf8');
  await fs.writeFile(path.join(extDir, 'app.html'), extFullHtml, 'utf8');
  console.log(`✓ Chrome Extension synced in: ${extDir}`);
}

buildStandalone().catch((err) => {
  console.error('Build error:', err);
  process.exit(1);
});
