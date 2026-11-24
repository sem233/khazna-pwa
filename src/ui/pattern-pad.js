/**
 * Khazna 3x3 Interactive Pattern Lock Pad (Mouse & Touch)
 *
 * - Pure SVG + Pointer Events (works effortlessly with mouse drag on PC & finger drag on mobile).
 * - Zero innerHTML, zero inline styles (strict CSP compliant).
 * - Automatically connects intermediate skipped dots (e.g. 0->2 selects 1, 0->8 selects 4).
 * - Encodes dots via encodePatternSecret() -> full Argon2id/PBKDF2 + AES-256-GCM key wrapping.
 */

import { encodePatternSecret, MIN_PATTERN_DOTS } from '../crypto/vault-crypto.js';
import { el, svgEl, triggerHaptic } from './dom.js';

const CENTERS = [
  { x: 50, y: 50 },  { x: 150, y: 50 },  { x: 250, y: 50 },
  { x: 50, y: 150 }, { x: 150, y: 150 }, { x: 250, y: 150 },
  { x: 50, y: 250 }, { x: 150, y: 250 }, { x: 250, y: 250 },
];

// Midpoint map for skipped straight/diagonal lines (Android pattern behavior)
const MIDPOINTS = new Map([
  ['0-2', 1], ['2-0', 1],
  ['3-5', 4], ['5-3', 4],
  ['6-8', 7], ['8-6', 7],
  ['0-6', 3], ['6-0', 3],
  ['1-7', 4], ['7-1', 4],
  ['2-8', 5], ['8-2', 5],
  ['0-8', 4], ['8-0', 4],
  ['2-6', 4], ['6-2', 4],
]);

export function createPatternPad({
  lang = 'ar',
  hint = '',
  onComplete = null,
  onChange = null,
  autoClearOnErrorMs = 800,
} = {}) {
  let selected = [];
  let dragging = false;
  let disabled = false;
  let clearTimer = null;

  const linesLayer = svgEl('g', { class: 'pattern-lines' });
  const liveLine = svgEl('line', {
    class: 'pattern-live-line hidden',
    x1: 0,
    y1: 0,
    x2: 0,
    y2: 0,
  });

  const dotNodes = [];
  const dotsLayer = svgEl('g', { class: 'pattern-dots' });

  for (let i = 0; i < 9; i++) {
    const { x, y } = CENTERS[i];
    const outer = svgEl('circle', {
      class: 'pattern-dot-ring',
      cx: x,
      cy: y,
      r: 24,
    });
    const core = svgEl('circle', {
      class: 'pattern-dot-core',
      cx: x,
      cy: y,
      r: 8,
    });
    const group = svgEl('g', { class: 'pattern-dot', 'data-dot': i }, outer, core);
    dotNodes.push(group);
    dotsLayer.appendChild(group);
  }

  const svg = svgEl(
    'svg',
    {
      class: 'pattern-svg',
      viewBox: '0 0 300 300',
      role: 'application',
      'aria-label': lang === 'en' ? '3x3 Unlock Pattern Pad' : 'لوحة رسم النمط ٣×٣',
    },
    linesLayer,
    liveLine,
    dotsLayer
  );

  const defaultHint = hint || (
    lang === 'en'
      ? 'Drag across 4+ dots with mouse or finger'
      : 'اسحب بالماوس أو الإصبع لتوصيل ٤ نقاط على الأقل'
  );
  const statusEl = el('div', { class: 'pattern-status' }, defaultHint);

  const renderState = () => {
    while (linesLayer.firstChild) linesLayer.removeChild(linesLayer.firstChild);
    for (let i = 0; i < dotNodes.length; i++) {
      dotNodes[i].classList.toggle('is-active', selected.includes(i));
    }
    for (let i = 1; i < selected.length; i++) {
      const a = CENTERS[selected[i - 1]];
      const b = CENTERS[selected[i]];
      linesLayer.appendChild(
        svgEl('line', {
          class: 'pattern-line',
          x1: a.x,
          y1: a.y,
          x2: b.x,
          y2: b.y,
        })
      );
    }
  };

  const reset = (customHint = null) => {
    if (clearTimer) {
      clearTimeout(clearTimer);
      clearTimer = null;
    }
    selected = [];
    dragging = false;
    svg.classList.remove('is-error', 'is-success');
    liveLine.classList.add('hidden');
    statusEl.textContent = customHint || defaultHint;
    renderState();
    if (onChange) onChange([]);
  };

  const setError = (msg = null) => {
    svg.classList.remove('is-success');
    svg.classList.add('is-error');
    if (msg) statusEl.textContent = msg;
    if (autoClearOnErrorMs > 0) {
      if (clearTimer) clearTimeout(clearTimer);
      clearTimer = setTimeout(() => reset(), autoClearOnErrorMs);
    }
  };

  const setSuccess = (msg = null) => {
    svg.classList.remove('is-error');
    svg.classList.add('is-success');
    if (msg) statusEl.textContent = msg;
  };

  const svgPointFromEvent = (ev) => {
    const rect = svg.getBoundingClientRect();
    if (!rect.width || !rect.height) return { x: -100, y: -100 };
    return {
      x: ((ev.clientX - rect.left) / rect.width) * 300,
      y: ((ev.clientY - rect.top) / rect.height) * 300,
    };
  };

  const hitTestDot = (pt, radius = 34) => {
    for (let i = 0; i < 9; i++) {
      const dx = pt.x - CENTERS[i].x;
      const dy = pt.y - CENTERS[i].y;
      if (dx * dx + dy * dy <= radius * radius) return i;
    }
    return -1;
  };

  const selectDot = (idx) => {
    if (idx < 0 || selected.includes(idx)) return false;
    if (selected.length > 0) {
      const prev = selected[selected.length - 1];
      const mid = MIDPOINTS.get(`${prev}-${idx}`);
      if (mid !== undefined && !selected.includes(mid)) {
        selected.push(mid);
      }
    }
    selected.push(idx);
    triggerHaptic(10);
    renderState();
    if (onChange) onChange([...selected]);
    return true;
  };

  const updateLiveLine = (pt) => {
    if (!dragging || selected.length === 0) {
      liveLine.classList.add('hidden');
      return;
    }
    const last = CENTERS[selected[selected.length - 1]];
    liveLine.setAttribute('x1', String(last.x));
    liveLine.setAttribute('y1', String(last.y));
    liveLine.setAttribute('x2', String(pt.x));
    liveLine.setAttribute('y2', String(pt.y));
    liveLine.classList.remove('hidden');
  };

  const finishDraw = () => {
    if (!dragging) return;
    dragging = false;
    liveLine.classList.add('hidden');

    if (selected.length === 0) return;
    if (selected.length < MIN_PATTERN_DOTS) {
      setError(
        lang === 'en'
          ? `Connect at least ${MIN_PATTERN_DOTS} dots`
          : `وصّل ${MIN_PATTERN_DOTS} نقاط على الأقل`
      );
      return;
    }

    const secret = encodePatternSecret(selected);
    if (onComplete) onComplete(secret, [...selected]);
  };

  svg.addEventListener('pointerdown', (ev) => {
    if (disabled) return;
    ev.preventDefault();
    if (clearTimer) {
      clearTimeout(clearTimer);
      clearTimer = null;
    }
    selected = [];
    svg.classList.remove('is-error', 'is-success');
    dragging = true;
    try {
      svg.setPointerCapture(ev.pointerId);
    } catch {
      // ignore if capture unavailable
    }
    const pt = svgPointFromEvent(ev);
    const hit = hitTestDot(pt, 38);
    if (hit !== -1) {
      selectDot(hit);
      updateLiveLine(pt);
    } else {
      renderState();
    }
  });

  svg.addEventListener('pointermove', (ev) => {
    if (!dragging || disabled) return;
    ev.preventDefault();
    const pt = svgPointFromEvent(ev);
    const hit = hitTestDot(pt, 34);
    if (hit !== -1) selectDot(hit);
    updateLiveLine(pt);
  });

  svg.addEventListener('pointerup', (ev) => {
    if (!dragging) return;
    ev.preventDefault();
    finishDraw();
  });

  svg.addEventListener('pointercancel', () => {
    finishDraw();
  });

  const clearBtn = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-sm btn-ghost',
      onClick: () => reset(),
    },
    lang === 'en' ? 'Clear Pattern' : 'إعادة الرسم'
  );

  const wrap = el(
    'div',
    { class: 'pattern-pad-wrap' },
    statusEl,
    svg,
    clearBtn
  );

  return {
    wrap,
    reset,
    setError,
    setSuccess,
    getDots: () => [...selected],
    getSecret: () => (selected.length >= MIN_PATTERN_DOTS ? encodePatternSecret(selected) : null),
    setDisabled: (val) => {
      disabled = Boolean(val);
      svg.classList.toggle('is-disabled', disabled);
    },
    setHint: (text) => {
      statusEl.textContent = text;
    },
  };
}
