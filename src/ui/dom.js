/**
 * Khazna Safe DOM & SVG Builder
 *
 * SECURITY INVARIANT:
 * - ZERO `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or inline `style="..."` anywhere.
 * - All user data is assigned strictly via `textContent` or safe DOM properties.
 * - All SVG icons and card brand emblems are constructed via `document.createElementNS`.
 */

import { formatError, t } from '../i18n/strings.js';
import { createPatternPad } from './pattern-pad.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

const ACCENT_MAP = new Map([
  ['#38bdf8', 'accent-sky'],
  ['#10b981', 'accent-emerald'],
  ['#a78bfa', 'accent-violet'],
  ['#f59e0b', 'accent-amber'],
  ['#f472b6', 'accent-rose'],
  ['#2dd4bf', 'accent-teal'],
  ['#fb7185', 'accent-coral'],
  ['#818cf8', 'accent-indigo'],
  ['#a3e635', 'accent-lime'],
  ['#e879f9', 'accent-fuchsia'],
  ['#22d3ee', 'accent-cyan'],
  ['#fb923c', 'accent-orange'],
  ['#94a3b8', 'accent-slate'],
]);

export const SECTION_COLOR_OPTIONS = Object.freeze([
  { hex: '#38bdf8', cls: 'accent-sky', nameAr: 'سماوي مشع', nameEn: 'Electric Sky' },
  { hex: '#10b981', cls: 'accent-emerald', nameAr: 'زمردي', nameEn: 'Emerald' },
  { hex: '#a78bfa', cls: 'accent-violet', nameAr: 'بنفسجي ملكي', nameEn: 'Royal Violet' },
  { hex: '#2dd4bf', cls: 'accent-teal', nameAr: 'فيروزي', nameEn: 'Ocean Teal' },
  { hex: '#f59e0b', cls: 'accent-amber', nameAr: 'كهرماني ذهبي', nameEn: 'Golden Amber' },
  { hex: '#f472b6', cls: 'accent-rose', nameAr: 'وردي نيون', nameEn: 'Neon Rose' },
  { hex: '#fb7185', cls: 'accent-coral', nameAr: 'مرجاني', nameEn: 'Coral Glow' },
  { hex: '#818cf8', cls: 'accent-indigo', nameAr: 'نيلي عميق', nameEn: 'Deep Indigo' },
  { hex: '#a3e635', cls: 'accent-lime', nameAr: 'ليموني', nameEn: 'Vibrant Lime' },
  { hex: '#e879f9', cls: 'accent-fuchsia', nameAr: 'أرجواني', nameEn: 'Fuchsia' },
  { hex: '#22d3ee', cls: 'accent-cyan', nameAr: 'سماوي جليدي', nameEn: 'Ice Cyan' },
  { hex: '#fb923c', cls: 'accent-orange', nameAr: 'برتقالي دافئ', nameEn: 'Sunset Orange' },
]);

export function accentClassForHex(hex) {
  return ACCENT_MAP.get(String(hex || '').toLowerCase()) || 'accent-sky';
}

/**
 * Picks the next unused section theme color & emoji so every new section gets a unique visual identity.
 */
export function pickNextUnusedSectionTheme(existingSections = [], emojiPool = []) {
  const usedColors = new Set(
    existingSections.map((s) => String(s?.data?.color || '').toLowerCase()).filter(Boolean)
  );
  const usedEmojis = new Set(
    existingSections.map((s) => String(s?.data?.emoji || '')).filter(Boolean)
  );

  const unusedColor = SECTION_COLOR_OPTIONS.find((c) => !usedColors.has(c.hex));
  const colorObj =
    unusedColor || SECTION_COLOR_OPTIONS[existingSections.length % SECTION_COLOR_OPTIONS.length];

  const unusedEmoji = emojiPool.find((em) => !usedEmojis.has(em));
  const emoji =
    unusedEmoji || (emojiPool.length > 0 ? emojiPool[existingSections.length % emojiPool.length] : '📁');

  return { hex: colorObj.hex, cls: colorObj.cls, emoji };
}

/**
 * Safely creates an HTML element with attributes, event listeners, and children.
 */
export function el(tag, attrs = null, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class' || k === 'className') {
        node.className = String(v);
      } else if (k === 'dataset' && typeof v === 'object') {
        for (const [dk, dv] of Object.entries(v)) {
          if (dv !== undefined && dv !== null) node.dataset[dk] = String(dv);
        }
      } else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (k === 'value' && ('value' in node)) {
        node.value = String(v);
      } else if (k === 'checked' && ('checked' in node)) {
        node.checked = Boolean(v);
      } else if (k === 'disabled' && ('disabled' in node)) {
        node.disabled = Boolean(v);
      } else if (k === 'style') {
        // Strictly forbidden by CSP policy — ignore any accidental style attribute
        continue;
      } else if (v === true) {
        node.setAttribute(k, '');
      } else {
        node.setAttribute(k, String(v));
      }
    }
  }
  appendChildren(node, children);
  return node;
}

export function appendChildren(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) {
      appendChildren(parent, child);
    } else if (child instanceof Node) {
      parent.appendChild(child);
    } else {
      parent.appendChild(document.createTextNode(String(child)));
    }
  }
}

export function clearNode(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

export function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || k === 'style') continue;
    node.setAttribute(k, String(v));
  }
  for (const child of children) {
    if (child instanceof Node) node.appendChild(child);
    else if (child !== null && child !== undefined) {
      node.appendChild(document.createTextNode(String(child)));
    }
  }
  return node;
}

const ICON_PATHS = {
  lock: [
    ['rect', { x: 3, y: 11, width: 18, height: 11, rx: 2, ry: 2 }],
    ['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }],
  ],
  key: [
    ['circle', { cx: 7.5, cy: 15.5, r: 4.5 }],
    ['path', { d: 'm21 2-9.6 9.6' }],
    ['path', { d: 'm15.5 7.5 3 3L22 7l-3-3' }],
  ],
  fingerprint: [
    ['path', { d: 'M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4' }],
    ['path', { d: 'M14 13.12c0 2.38 0 6.38-1 8.88' }],
    ['path', { d: 'M17.29 21.02c.12-.6.43-2.3.5-3.02' }],
    ['path', { d: 'M2 12a10 10 0 0 1 18-6' }],
    ['path', { d: 'M2 16h.01' }],
    ['path', { d: 'M21.8 16c.2-2 .131-5.354 0-6' }],
    ['path', { d: 'M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2' }],
    ['path', { d: 'M8.65 22c.21-.66.45-1.32.57-2' }],
    ['path', { d: 'M9 6.8a6 6 0 0 1 9 5.2v2' }],
  ],
  card: [
    ['rect', { x: 2, y: 5, width: 20, height: 14, rx: 2 }],
    ['line', { x1: 2, y1: 10, x2: 22, y2: 10 }],
  ],
  note: [
    ['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }],
    ['polyline', { points: '14 2 14 8 20 8' }],
    ['line', { x1: 8, y1: 13, x2: 16, y2: 13 }],
    ['line', { x1: 8, y1: 17, x2: 13, y2: 17 }],
  ],
  chart: [
    ['path', { d: 'M21.21 15.89A10 10 0 1 1 8 2.83' }],
    ['path', { d: 'M22 12A10 10 0 0 0 12 2v10z' }],
  ],
  settings: [
    ['circle', { cx: 12, cy: 12, r: 3 }],
    ['path', { d: 'M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z' }],
  ],
  copy: [
    ['rect', { x: 9, y: 9, width: 13, height: 13, rx: 2, ry: 2 }],
    ['path', { d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' }],
  ],
  eye: [
    ['path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }],
    ['circle', { cx: 12, cy: 12, r: 3 }],
  ],
  star: [
    ['polygon', { points: '12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2' }],
  ],
  plus: [
    ['line', { x1: 12, y1: 5, x2: 12, y2: 19 }],
    ['line', { x1: 5, y1: 12, x2: 19, y2: 12 }],
  ],
  search: [
    ['circle', { cx: 11, cy: 11, r: 8 }],
    ['line', { x1: 21, y1: 21, x2: 16.65, y2: 16.65 }],
  ],
  trash: [
    ['polyline', { points: '3 6 5 6 21 6' }],
    ['path', { d: 'M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2' }],
  ],
  edit: [
    ['path', { d: 'M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7' }],
    ['path', { d: 'M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z' }],
  ],
  shield: [
    ['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }],
  ],
  flip: [
    ['polyline', { points: '17 1 21 5 17 9' }],
    ['path', { d: 'M3 11V9a4 4 0 0 1 4-4h14' }],
    ['polyline', { points: '7 23 3 19 7 15' }],
    ['path', { d: 'M21 13v2a4 4 0 0 1-4 4H3' }],
  ],
  close: [
    ['line', { x1: 18, y1: 6, x2: 6, y2: 18 }],
    ['line', { x1: 6, y1: 6, x2: 18, y2: 18 }],
  ],
  check: [
    ['polyline', { points: '20 6 9 17 4 12' }],
  ],
  refresh: [
    ['polyline', { points: '23 4 23 10 17 10' }],
    ['path', { d: 'M20.49 15a9 9 0 1 1-2.12-9.36L23 10' }],
  ],
  download: [
    ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }],
    ['polyline', { points: '7 10 12 15 17 10' }],
    ['line', { x1: 12, y1: 15, x2: 12, y2: 3 }],
  ],
  upload: [
    ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }],
    ['polyline', { points: '17 8 12 3 7 8' }],
    ['line', { x1: 12, y1: 3, x2: 12, y2: 15 }],
  ],
  pin: [
    ['path', { d: 'M12 17v5' }],
    ['path', { d: 'M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16h14v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1z' }],
  ],
  link: [
    ['path', { d: 'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71' }],
    ['path', { d: 'M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71' }],
  ],
  share: [
    ['circle', { cx: 18, cy: 5, r: 3 }],
    ['circle', { cx: 6, cy: 12, r: 3 }],
    ['circle', { cx: 18, cy: 19, r: 3 }],
    ['line', { x1: 8.59, y1: 13.51, x2: 15.42, y2: 17.49 }],
    ['line', { x1: 15.41, y1: 6.51, x2: 8.59, y2: 10.49 }],
  ],
};

export function svgIcon(name, size = 20, filled = false) {
  const shapes = ICON_PATHS[name] || ICON_PATHS.shield;
  return svgEl(
    'svg',
    {
      width: size,
      height: size,
      viewBox: '0 0 24 24',
      fill: filled ? 'currentColor' : 'none',
      stroke: 'currentColor',
      'stroke-width': 2,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
      'aria-hidden': 'true',
    },
    ...shapes.map(([tag, attrs]) => svgEl(tag, attrs))
  );
}

/**
 * Inline SVG EMV chip & contactless icon for the 3D bank card.
 */
export function emvChipSvg() {
  return svgEl(
    'svg',
    { width: 42, height: 32, viewBox: '0 0 42 32', 'aria-hidden': 'true' },
    svgEl('rect', { x: 1, y: 1, width: 40, height: 30, rx: 6, fill: '#e2c275', stroke: '#b48a34', 'stroke-width': 1.5 }),
    svgEl('line', { x1: 1, y1: 11, x2: 41, y2: 11, stroke: '#926c21', 'stroke-width': 1.2 }),
    svgEl('line', { x1: 1, y1: 21, x2: 41, y2: 21, stroke: '#926c21', 'stroke-width': 1.2 }),
    svgEl('line', { x1: 15, y1: 1, x2: 15, y2: 31, stroke: '#926c21', 'stroke-width': 1.2 }),
    svgEl('line', { x1: 27, y1: 1, x2: 27, y2: 31, stroke: '#926c21', 'stroke-width': 1.2 })
  );
}

export function contactlessSvg() {
  return svgEl(
    'svg',
    { width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'aria-hidden': 'true' },
    svgEl('path', { d: 'M8.5 16.5a5 5 0 0 1 0-9' }),
    svgEl('path', { d: 'M12 19a9 9 0 0 1 0-14' }),
    svgEl('path', { d: 'M15.5 21.5a13 13 0 0 1 0-19' })
  );
}

export function brandLogoSvg(brand) {
  if (brand === 'mastercard') {
    return svgEl(
      'svg',
      { width: 48, height: 30, viewBox: '0 0 48 30', 'aria-label': 'Mastercard' },
      svgEl('circle', { cx: 18, cy: 15, r: 11, fill: '#eb001b', opacity: '0.92' }),
      svgEl('circle', { cx: 30, cy: 15, r: 11, fill: '#f79e1b', opacity: '0.88' })
    );
  }
  if (brand === 'visa') {
    return svgEl(
      'svg',
      { width: 54, height: 26, viewBox: '0 0 54 26', 'aria-label': 'Visa' },
      svgEl('text', { x: 2, y: 20, fill: '#ffffff', 'font-size': 18, 'font-weight': 800, 'font-style': 'italic', 'letter-spacing': '1' }, 'VISA')
    );
  }
  if (brand === 'meeza') {
    return svgEl(
      'svg',
      { width: 64, height: 26, viewBox: '0 0 64 26', 'aria-label': 'Meeza' },
      svgEl('rect', { x: 1, y: 3, width: 62, height: 20, rx: 6, fill: 'rgba(16,185,129,0.28)', stroke: '#34d399', 'stroke-width': 1.2 }),
      svgEl('text', { x: 32, y: 17, fill: '#ffffff', 'font-size': 11, 'font-weight': 800, 'text-anchor': 'middle' }, 'MEEZA')
    );
  }
  if (brand === 'amex') {
    return svgEl(
      'svg',
      { width: 58, height: 26, viewBox: '0 0 58 26', 'aria-label': 'American Express' },
      svgEl('rect', { x: 1, y: 3, width: 56, height: 20, rx: 5, fill: 'rgba(56,189,248,0.28)', stroke: '#7dd3fc', 'stroke-width': 1.2 }),
      svgEl('text', { x: 29, y: 17, fill: '#ffffff', 'font-size': 11, 'font-weight': 800, 'text-anchor': 'middle' }, 'AMEX')
    );
  }
  if (brand === 'discover') {
    return svgEl(
      'svg',
      { width: 70, height: 26, viewBox: '0 0 70 26', 'aria-label': 'Discover' },
      svgEl('text', { x: 35, y: 18, fill: '#fbbf24', 'font-size': 12, 'font-weight': 800, 'text-anchor': 'middle' }, 'DISCOVER')
    );
  }
  if (brand === 'unionpay') {
    return svgEl(
      'svg',
      { width: 66, height: 26, viewBox: '0 0 66 26', 'aria-label': 'UnionPay' },
      svgEl('rect', { x: 1, y: 3, width: 64, height: 20, rx: 5, fill: 'rgba(244,63,94,0.25)', stroke: '#fda4af', 'stroke-width': 1 }),
      svgEl('text', { x: 33, y: 17, fill: '#ffffff', 'font-size': 10, 'font-weight': 700, 'text-anchor': 'middle' }, 'UnionPay')
    );
  }
  return svgEl(
    'svg',
    { width: 42, height: 24, viewBox: '0 0 42 24', 'aria-label': 'Card' },
    svgEl('rect', { x: 2, y: 3, width: 38, height: 18, rx: 4, fill: 'none', stroke: 'rgba(255,255,255,0.65)', 'stroke-width': 1.5 }),
    svgEl('line', { x1: 2, y1: 9, x2: 40, y2: 9, stroke: 'rgba(255,255,255,0.65)', 'stroke-width': 1.5 })
  );
}

/**
 * Triggers gentle haptic vibration on Android devices when available.
 */
export function triggerHaptic(pattern = 18) {
  try {
    if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
      navigator.vibrate(pattern);
    }
  } catch {
    // ignore unsupported environments
  }
}

/**
 * Displays a transient glassmorphism toast message.
 */
export function showToast(message, kind = 'info', durationMs = 2800) {
  const root = document.getElementById('toast-root');
  if (!root) return;
  const toast = el(
    'div',
    { class: `toast toast-${kind}`, role: 'status' },
    kind === 'success' ? svgIcon('check', 16) : null,
    el('span', null, message)
  );
  root.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, durationMs);
}

/**
 * Opens an accessible bottom-sheet modal with ESC & backdrop dismissal.
 */
export function openBottomSheet({ title, content, onClose }) {
  const modalRoot = document.getElementById('modal-root');
  if (!modalRoot) return { close: () => {} };

  const close = () => {
    document.removeEventListener('keydown', onKey);
    backdrop.remove();
    if (typeof onClose === 'function') onClose();
  };

  const onKey = (e) => {
    if (e.key === 'Escape') close();
  };
  document.addEventListener('keydown', onKey);

  const closeBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-icon btn-ghost',
      'aria-label': 'Close',
      onClick: close,
    },
    svgIcon('close', 20)
  );

  const panel = el(
    'div',
    { class: 'sheet-panel', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    el('div', { class: 'sheet-header' }, el('h2', { class: 'sheet-title' }, title), closeBtn),
    content
  );

  const backdrop = el(
    'div',
    {
      class: 'sheet-backdrop',
      onClick: (e) => {
        if (e.target === backdrop) close();
      },
    },
    panel
  );

  modalRoot.appendChild(backdrop);
  return { close, panel };
}

/**
 * Attaches press-and-hold reveal behavior with automatic 10-second auto-hide fallback
 * (also supports keyboard Space/Enter toggle with 10s auto-hide for accessibility).
 */
export function attachHoldToReveal(button, { onReveal, onHide, autoHideMs = 10000 }) {
  let hideTimer = null;
  let revealed = false;

  const reveal = () => {
    if (!revealed) {
      revealed = true;
      onReveal();
    }
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(hide, autoHideMs);
  };

  const hide = () => {
    if (hideTimer) {
      clearTimeout(hideTimer);
      hideTimer = null;
    }
    if (revealed) {
      revealed = false;
      onHide();
    }
  };

  button.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    reveal();
  });
  button.addEventListener('pointerup', hide);
  button.addEventListener('pointercancel', hide);
  button.addEventListener('pointerleave', hide);
  button.addEventListener('click', (e) => {
    // Allow quick keyboard/assistive click to reveal briefly for 10s
    if (e.detail === 0) {
      if (revealed) hide();
      else reveal();
    }
  });
}

/**
 * Prompts the user to re-authenticate with Master Password or Biometrics before sensitive actions.
 * Resolves true if verified, false if cancelled.
 */
export function requestReauth({ session, lang }) {
  if (!session.settings?.reauthSensitive) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      sheet.close();
      resolve(ok);
    };

    let activeMethod = session.hasPatternUnlock ? 'pattern' : 'password';
    const host = el('div', { class: 'settings-group' });
    const errBox = el('div', { class: 'banner banner-danger hidden', role: 'alert' });
    const bioState = session.getBiometricState();

    const bioBtn = bioState.enabled
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-block',
            onClick: async () => {
              errBox.classList.add('hidden');
              try {
                await session.verifyReauth({ useBiometric: true });
                finish(true);
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove('hidden');
              }
            },
          },
          svgIcon('fingerprint', 18),
          t(lang, 'unlockWithFingerprint')
        )
      : null;

    const renderContent = () => {
      clearNode(host);
      host.appendChild(el('p', { class: 'settings-row-desc' }, t(lang, 'reauthSubtitle')));
      host.appendChild(errBox);

      if (activeMethod === 'pattern') {
        const pad = createPatternPad({
          lang,
          hint: t(lang, 'patternDrawUnlock'),
          onComplete: async (secret) => {
            errBox.classList.add('hidden');
            pad.setDisabled(true);
            try {
              await session.verifyReauth({ masterPassword: secret });
              pad.setSuccess();
              finish(true);
            } catch (err) {
              pad.setDisabled(false);
              pad.setError(formatError(err, lang));
              errBox.textContent = formatError(err, lang);
              errBox.classList.remove('hidden');
            }
          },
        });
        host.appendChild(pad.wrap);
        if (session.hasPasswordUnlock) {
          host.appendChild(
            el(
              'button',
              {
                type: 'button',
                class: 'btn btn-ghost btn-sm btn-block',
                onClick: () => {
                  activeMethod = 'password';
                  renderContent();
                },
              },
              t(lang, 'usePasswordUnlock')
            )
          );
        }
      } else {
        const pwdInput = el('input', {
          type: 'password',
          class: 'input ltr-value',
          autocomplete: 'off',
          spellcheck: 'false',
          placeholder: t(lang, 'masterPasswordLabel'),
        });
        const submitBtn = el('button', { type: 'submit', class: 'btn btn-primary btn-block' }, t(lang, 'confirmBtn'));
        const form = el(
          'form',
          {
            onSubmit: async (e) => {
              e.preventDefault();
              errBox.classList.add('hidden');
              submitBtn.disabled = true;
              try {
                await session.verifyReauth({ masterPassword: pwdInput.value });
                pwdInput.value = '';
                finish(true);
              } catch (err) {
                errBox.textContent = formatError(err, lang);
                errBox.classList.remove('hidden');
              } finally {
                submitBtn.disabled = false;
              }
            },
          },
          el('div', { class: 'field' }, pwdInput),
          submitBtn
        );
        host.appendChild(form);
        if (session.hasPatternUnlock) {
          host.appendChild(
            el(
              'button',
              {
                type: 'button',
                class: 'btn btn-ghost btn-sm btn-block',
                onClick: () => {
                  activeMethod = 'pattern';
                  renderContent();
                },
              },
              t(lang, 'usePatternUnlock')
            )
          );
        }
        setTimeout(() => pwdInput.focus(), 60);
      }

      if (bioBtn) host.appendChild(bioBtn);
    };

    renderContent();

    const sheet = openBottomSheet({
      title: t(lang, 'reauthTitle'),
      content: host,
      onClose: () => {
        if (!settled) {
          settled = true;
          resolve(false);
        }
      },
    });
  });
}

/**
 * Smoothly animates a numeric counter (respecting prefers-reduced-motion).
 */
export function animateCounter(node, target) {
  const num = Number(target) || 0;
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced || num === 0) {
    node.textContent = String(num);
    return;
  }
  const duration = 420;
  const start = performance.now();
  const step = (ts) => {
    const progress = Math.min(1, (ts - start) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    node.textContent = String(Math.round(num * eased));
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
