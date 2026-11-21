/**
 * Khazna 3D Bank Cards View & Live Interactive Editor
 *
 * - Realistic 3D card (EMV chip SVG, contactless SVG, brand SVG, embossed LTR number,
 *   holder name, expiry) with smooth 3D flip to back (magnetic stripe, signature strip, CVV, PIN)
 * - Editor card starts EMPTY (placeholder dots) and fills live as user types
 * - Luhn validation, brand auto-detect (Visa/MC/Amex/Meeza/Discover/UnionPay) + manual override
 * - Partial card support (Samsung Pass first 6 + last 4 digits clearly marked)
 * - Number, CVV, PIN masked by default; press-and-hold reveal (+ optional re-auth for CVV/PIN)
 * - Copy button on every field + Copy All
 */

import {
  CARD_BRANDS,
  CARD_THEMES,
  detectCardBrand,
  formatCardCopyAll,
  formatCardNumber,
  formatExpiry,
  isPartialCardNumber,
  maskCardNumber,
  normalizeCardInput,
  validateLuhn,
} from '../domain/cards.js';
import { formatError, t } from '../i18n/strings.js';
import {
  attachHoldToReveal,
  brandLogoSvg,
  clearNode,
  contactlessSvg,
  el,
  emvChipSvg,
  openBottomSheet,
  requestReauth,
  showToast,
  svgIcon,
  triggerHaptic,
} from './dom.js';

/**
 * Builds an interactive 3D bank card widget (used in both the vault grid and the live editor).
 */
function build3DBankCardWidget({
  data,
  lang,
  masked = true,
  isPreview = false,
  revealedSecrets = { number: false, cvv: false, pin: false },
}) {
  const brand = detectCardBrand(data.number, data.brandOverride);
  const theme = data.theme || 'obsidian';

  const numberDisplay = isPreview
    ? (data.number ? formatCardNumber(data.number, brand) : '•••• •••• •••• ••••')
    : (revealedSecrets.number || !masked
        ? (data.number ? formatCardNumber(data.number, brand) : '•••• •••• •••• ••••')
        : maskCardNumber(data.number, brand));

  const cvvDisplay = (isPreview || revealedSecrets.cvv || !masked)
    ? (data.cvv || '•••')
    : '•••';

  const pinDisplay = (isPreview || revealedSecrets.pin || !masked)
    ? (data.pin || '••••')
    : '••••';

  const brandSlot = el('div', { class: 'card-brand-slot' }, brandLogoSvg(brand));
  const labelNode = el('div', { class: 'card-label-name' }, data.cardName || (lang === 'en' ? 'Card Label' : 'اسم البطاقة'));
  const bankNode = el('div', { class: 'card-bank-name' }, data.bankName || (lang === 'en' ? 'Bank' : 'البنك'));
  const numberNode = el('div', { class: 'card-number-embossed', 'data-testid': isPreview ? 'preview-card-number' : undefined }, numberDisplay);
  const holderNode = el('div', { class: 'card-meta-val ltr-value' }, (data.holderName || 'CARDHOLDER NAME').toUpperCase());
  const expiryNode = el('div', { class: 'card-meta-val ltr-value' }, data.expiry || 'MM/YY');
  const cvvNode = el('span', { class: 'ltr-inline mono' }, cvvDisplay);
  const pinNode = el('span', { class: 'ltr-inline mono' }, pinDisplay);

  const front = el(
    'div',
    { class: 'bank-card-face bank-card-front' },
    el(
      'div',
      { class: 'card-top-row' },
      el('div', { class: 'card-label-block' }, labelNode, bankNode),
      brandSlot
    ),
    el('div', { class: 'card-chip-row' }, emvChipSvg(), contactlessSvg()),
    numberNode,
    el(
      'div',
      { class: 'card-bottom-row' },
      el('div', { class: 'card-meta-col' }, el('span', { class: 'card-meta-label' }, 'CARDHOLDER'), holderNode),
      el('div', { class: 'card-meta-col' }, el('span', { class: 'card-meta-label' }, 'EXPIRES'), expiryNode)
    )
  );

  const back = el(
    'div',
    { class: 'bank-card-face bank-card-back' },
    el('div', { class: 'card-mag-stripe', 'aria-hidden': 'true' }),
    el(
      'div',
      { class: 'card-back-body' },
      el(
        'div',
        { class: 'card-signature-strip' },
        el('span', null, 'CVV / CVC'),
        cvvNode
      ),
      el(
        'div',
        { class: 'card-back-pin-row' },
        el('span', null, 'PIN'),
        pinNode
      )
    )
  );

  const inner3d = el('div', { class: 'bank-card-3d' }, front, back);
  const scene = el('div', { class: `bank-card-scene card-theme-${theme}` }, inner3d);

  return {
    scene,
    inner3d,
    setFlipped: (flipped) => inner3d.classList.toggle('is-flipped', Boolean(flipped)),
    toggleFlip: () => inner3d.classList.toggle('is-flipped'),
    updateLive: (next) => {
      const b = detectCardBrand(next.number, next.brandOverride);
      scene.className = `bank-card-scene card-theme-${next.theme || 'obsidian'}`;
      clearNode(brandSlot);
      brandSlot.appendChild(brandLogoSvg(b));
      labelNode.textContent = next.cardName || (lang === 'en' ? 'Card Label' : 'اسم البطاقة');
      bankNode.textContent = next.bankName || (lang === 'en' ? 'Bank' : 'البنك');
      numberNode.textContent = next.number ? formatCardNumber(next.number, b) : '•••• •••• •••• ••••';
      holderNode.textContent = (next.holderName || 'CARDHOLDER NAME').toUpperCase();
      expiryNode.textContent = next.expiry || 'MM/YY';
      cvvNode.textContent = next.cvv || '•••';
      pinNode.textContent = next.pin || '••••';
    },
    setNumberText: (txt) => { numberNode.textContent = txt; },
    setCvvText: (txt) => { cvvNode.textContent = txt; },
    setPinText: (txt) => { pinNode.textContent = txt; },
  };
}

export function renderCardsView({ session, lang, cards, onRefresh }) {
  const container = el('div', { class: 'settings-group view-enter' });

  const copySecret = async (val, label) => {
    if (!val) return;
    try {
      await session.clipboard.copySecret(val, session.settings?.clipboardClearSec ?? 30);
      triggerHaptic();
      showToast(`${t(lang, 'copiedToast')}: ${label}`, 'success');
    } catch (err) {
      showToast(formatError(err, lang), 'error');
    }
  };

  if (cards.length === 0) {
    container.appendChild(
      el(
        'div',
        { class: 'glass-card empty-state' },
        svgIcon('card', 40),
        el('h3', null, t(lang, 'emptyCards')),
        el('p', null, t(lang, 'emptyCardsSub'))
      )
    );
    return container;
  }

  const grid = el('div', { class: 'cards-grid', 'data-testid': 'cards-grid' });

  for (const card of cards) {
    const d = card.data || {};
    const brand = detectCardBrand(d.number, d.brandOverride);
    const partial = Boolean(d.partial || isPartialCardNumber(d.number));
    const widget = build3DBankCardWidget({ data: d, lang, masked: true, isPreview: false });

    let reauthedCvv = false;

    const flipBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-sm',
        'aria-label': `${t(lang, 'flipCard')} ${d.cardName}`,
        onClick: () => {
          triggerHaptic(10);
          widget.toggleFlip();
        },
      },
      svgIcon('flip', 15),
      t(lang, 'flipCard')
    );

    const holdNumBtn = el(
      'button',
      { type: 'button', class: 'btn btn-sm', title: t(lang, 'holdToReveal') },
      svgIcon('eye', 15),
      t(lang, 'cardNumberLabel')
    );
    attachHoldToReveal(holdNumBtn, {
      onReveal: () => widget.setNumberText(formatCardNumber(d.number, brand)),
      onHide: () => widget.setNumberText(maskCardNumber(d.number, brand)),
      autoHideMs: 10000,
    });

    const revealCvvBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-sm',
        onClick: async () => {
          if (!reauthedCvv) {
            const ok = await requestReauth({ session, lang });
            if (!ok) return;
            reauthedCvv = true;
          }
          widget.setFlipped(true);
          widget.setCvvText(d.cvv || '—');
          widget.setPinText(d.pin || '—');
          setTimeout(() => {
            widget.setCvvText('•••');
            widget.setPinText('••••');
            reauthedCvv = false;
          }, 10000);
        },
      },
      svgIcon('eye', 15),
      'CVV / PIN'
    );

    const copyActions = el(
      'div',
      { class: 'entry-actions-row' },
      d.number
        ? el('button', { type: 'button', class: 'btn btn-sm', onClick: () => copySecret(normalizeCardInput(d.number), t(lang, 'cardNumberLabel')) }, svgIcon('copy', 14), t(lang, 'cardNumberLabel'))
        : null,
      d.holderName
        ? el('button', { type: 'button', class: 'btn btn-sm', onClick: () => copySecret(d.holderName, t(lang, 'holderNameLabel')) }, svgIcon('copy', 14), t(lang, 'holderNameLabel'))
        : null,
      d.expiry
        ? el('button', { type: 'button', class: 'btn btn-sm', onClick: () => copySecret(d.expiry, t(lang, 'expiryLabel')) }, svgIcon('copy', 14), d.expiry)
        : null,
      d.cvv
        ? el('button', {
            type: 'button',
            class: 'btn btn-sm',
            onClick: async () => {
              const ok = await requestReauth({ session, lang });
              if (!ok) return;
              await copySecret(d.cvv, 'CVV');
            },
          }, svgIcon('copy', 14), 'CVV')
        : null,
      d.pin
        ? el('button', {
            type: 'button',
            class: 'btn btn-sm',
            onClick: async () => {
              const ok = await requestReauth({ session, lang });
              if (!ok) return;
              await copySecret(d.pin, 'PIN');
            },
          }, svgIcon('copy', 14), 'PIN')
        : null,
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-sm btn-primary',
          onClick: async () => {
            if (d.cvv || d.pin) {
              const ok = await requestReauth({ session, lang });
              if (!ok) return;
            }
            await copySecret(formatCardCopyAll(d, lang), t(lang, 'copyAll'));
          },
        },
        svgIcon('copy', 14),
        t(lang, 'copyAll')
      )
    );

    const wrapper = el(
      'article',
      { class: 'glass-card glass-card-compact bank-card-wrapper stagger-item' },
      widget.scene,
      partial ? el('div', { class: 'banner banner-warn' }, el('span', null, t(lang, 'partialCardBadge'))) : null,
      el(
        'div',
        { class: 'entry-actions-row' },
        flipBtn,
        holdNumBtn,
        (d.cvv || d.pin) ? revealCvvBtn : null,
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm',
            'aria-label': `${t(lang, 'edit')} ${d.cardName}`,
            onClick: () => openCardEditorSheet({ session, lang, card, onSaved: onRefresh }),
          },
          svgIcon('edit', 14),
          t(lang, 'edit')
        ),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-sm btn-danger',
            'aria-label': `${t(lang, 'delete')} ${d.cardName}`,
            onClick: async () => {
              await session.trashRecord(card.id);
              showToast(t(lang, 'delete'), 'info');
              await onRefresh();
            },
          },
          svgIcon('trash', 14)
        )
      ),
      copyActions
    );

    grid.appendChild(wrapper);
  }

  container.appendChild(grid);
  return container;
}

/**
 * Interactive Bottom Sheet with Live 3D Card Preview (starts EMPTY with placeholder dots and fills live!).
 */
export function openCardEditorSheet({ session, lang, card = null, onSaved }) {
  const init = card?.data || {
    cardName: '',
    bankName: '',
    holderName: '',
    number: '',
    expiry: '',
    cvv: '',
    pin: '',
    notes: '',
    theme: 'aurora',
    brandOverride: 'auto',
  };

  const state = { ...init };
  const preview = build3DBankCardWidget({ data: state, lang, masked: false, isPreview: true });

  const luhnBadge = el('div', { class: 'settings-row-desc' }, '');
  const syncLive = () => {
    preview.updateLive(state);
    const num = normalizeCardInput(state.number);
    if (!num) {
      luhnBadge.textContent = '';
    } else if (isPartialCardNumber(num)) {
      luhnBadge.textContent = t(lang, 'partialCardBadge');
    } else if (num.length >= 13) {
      const ok = validateLuhn(num);
      luhnBadge.textContent = ok ? t(lang, 'luhnValid') : t(lang, 'luhnInvalid');
    } else {
      luhnBadge.textContent = '';
    }
  };

  const nameIn = el('input', {
    id: 'ce-name',
    type: 'text',
    class: 'input',
    value: state.cardName,
    required: true,
    autocomplete: 'off',
    placeholder: lang === 'en' ? 'e.g. Salary Card' : 'مثال: بطاقة الراتب',
    onInput: (e) => { state.cardName = e.target.value; syncLive(); },
  });
  const bankIn = el('input', {
    id: 'ce-bank',
    type: 'text',
    class: 'input',
    value: state.bankName,
    autocomplete: 'off',
    onInput: (e) => { state.bankName = e.target.value; syncLive(); },
  });
  const holderIn = el('input', {
    id: 'ce-holder',
    type: 'text',
    class: 'input ltr-value',
    value: state.holderName,
    autocomplete: 'off',
    spellcheck: 'false',
    onInput: (e) => { state.holderName = e.target.value; syncLive(); },
  });
  const numIn = el('input', {
    id: 'ce-num',
    type: 'text',
    inputmode: 'numeric',
    class: 'input ltr-value',
    value: formatCardNumber(state.number, detectCardBrand(state.number, state.brandOverride)),
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: '4532 •••• •••• ••••',
    onFocus: () => preview.setFlipped(false),
    onInput: (e) => {
      state.number = normalizeCardInput(e.target.value).slice(0, 19);
      syncLive();
    },
  });
  const expIn = el('input', {
    id: 'ce-exp',
    type: 'text',
    inputmode: 'numeric',
    class: 'input ltr-value',
    value: state.expiry,
    maxlength: 5,
    autocomplete: 'off',
    placeholder: 'MM/YY',
    onFocus: () => preview.setFlipped(false),
    onInput: (e) => {
      const f = formatExpiry(e.target.value);
      e.target.value = f;
      state.expiry = f;
      syncLive();
    },
  });
  const cvvIn = el('input', {
    id: 'ce-cvv',
    type: 'password',
    inputmode: 'numeric',
    class: 'input ltr-value',
    value: state.cvv,
    maxlength: 4,
    autocomplete: 'off',
    spellcheck: 'false',
    onFocus: () => preview.setFlipped(true),
    onInput: (e) => { state.cvv = e.target.value.replace(/\D+/g, '').slice(0, 4); syncLive(); },
  });
  const pinIn = el('input', {
    id: 'ce-pin',
    type: 'password',
    inputmode: 'numeric',
    class: 'input ltr-value',
    value: state.pin,
    maxlength: 8,
    autocomplete: 'off',
    spellcheck: 'false',
    onFocus: () => preview.setFlipped(true),
    onInput: (e) => { state.pin = e.target.value.replace(/\D+/g, '').slice(0, 8); syncLive(); },
  });
  const brandSel = el(
    'select',
    {
      id: 'ce-brand',
      class: 'select',
      onChange: (e) => { state.brandOverride = e.target.value; syncLive(); },
    },
    ...CARD_BRANDS.map((b) => el('option', { value: b.id, selected: state.brandOverride === b.id }, lang === 'en' ? b.labelEn : b.labelAr))
  );
  const themeSel = el(
    'select',
    {
      id: 'ce-theme',
      class: 'select',
      onChange: (e) => { state.theme = e.target.value; syncLive(); },
    },
    ...CARD_THEMES.map((th) => el('option', { value: th.id, selected: state.theme === th.id }, lang === 'en' ? th.labelEn : th.labelAr))
  );
  const notesIn = el('textarea', { id: 'ce-notes', class: 'textarea', autocomplete: 'off' }, state.notes);

  syncLive();

  const form = el(
    'form',
    {
      onSubmit: async (e) => {
        e.preventDefault();
        if (!state.cardName.trim()) return;
        await session.saveRecord({
          id: card?.id || null,
          type: 'card',
          createdAt: card?.createdAt,
          data: {
            ...state,
            cardName: state.cardName.trim(),
            bankName: state.bankName.trim(),
            holderName: state.holderName.trim(),
            number: normalizeCardInput(state.number),
            notes: notesIn.value,
            partial: isPartialCardNumber(state.number),
          },
        });
        sheet.close();
        showToast(t(lang, 'save'), 'success');
        onSaved && (await onSaved());
      },
    },
    el(
      'div',
      { class: 'settings-group' },
      preview.scene,
      el(
        'button',
        { type: 'button', class: 'btn btn-sm', onClick: () => preview.toggleFlip() },
        svgIcon('flip', 15),
        t(lang, 'flipCard')
      )
    ),
    el('div', { class: 'field' }),
    el('div', { class: 'form-grid-2' },
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-name' }, t(lang, 'cardNameLabel')), nameIn),
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-bank' }, t(lang, 'bankNameLabel')), bankIn)
    ),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-holder' }, t(lang, 'holderNameLabel')), holderIn),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-num' }, t(lang, 'cardNumberLabel')), numIn, luhnBadge),
    el('div', { class: 'form-grid-2' },
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-exp' }, t(lang, 'expiryLabel')), expIn),
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-cvv' }, t(lang, 'cvvLabel')), cvvIn)
    ),
    el('div', { class: 'form-grid-2' },
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-pin' }, t(lang, 'pinLabel')), pinIn),
      el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-brand' }, t(lang, 'cardBrandLabel')), brandSel)
    ),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-theme' }, t(lang, 'cardThemeLabel')), themeSel),
    el('div', { class: 'field' }, el('label', { class: 'field-label', for: 'ce-notes' }, t(lang, 'notesLabel')), notesIn),
    el(
      'div',
      { class: 'form-grid-2' },
      el('button', { type: 'button', class: 'btn', onClick: () => sheet.close() }, t(lang, 'cancel')),
      el('button', { type: 'submit', class: 'btn btn-primary' }, t(lang, 'save'))
    )
  );

  const sheet = openBottomSheet({
    title: card ? t(lang, 'editCard') : t(lang, 'addCard'),
    content: form,
  });
}
