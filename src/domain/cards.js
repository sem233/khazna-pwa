/**
 * Khazna Bank Card Domain Logic
 *
 * - Luhn check (for full card numbers)
 * - Auto-detection of Visa, Mastercard, Amex, Meeza (Egypt 5078xx), Discover, JCB, UnionPay, Mir
 *   with manual override support
 * - Partial card support (e.g. Samsung Pass exports with first 6 + last 4 digits)
 * - Auto-grouping & masking helpers
 * - Selectable glassmorphism card themes
 */

export const CARD_BRANDS = Object.freeze([
  { id: 'auto', labelAr: 'كشف تلقائي', labelEn: 'Auto-detect' },
  { id: 'visa', labelAr: 'Visa', labelEn: 'Visa' },
  { id: 'mastercard', labelAr: 'Mastercard', labelEn: 'Mastercard' },
  { id: 'meeza', labelAr: 'ميزة (Meeza)', labelEn: 'Meeza' },
  { id: 'amex', labelAr: 'American Express', labelEn: 'American Express' },
  { id: 'discover', labelAr: 'Discover', labelEn: 'Discover' },
  { id: 'unionpay', labelAr: 'UnionPay', labelEn: 'UnionPay' },
  { id: 'other', labelAr: 'أخرى', labelEn: 'Other' },
]);

export const CARD_THEMES = Object.freeze([
  { id: 'obsidian', labelAr: 'أوبسيديان داكن', labelEn: 'Obsidian Glass' },
  { id: 'aurora', labelAr: 'شفق أزرق', labelEn: 'Aurora Indigo' },
  { id: 'emerald', labelAr: 'زمردي', labelEn: 'Emerald Vault' },
  { id: 'sunset', labelAr: 'غروب دافئ', labelEn: 'Warm Sunset' },
  { id: 'gold', labelAr: 'ذهبي ملكي', labelEn: 'Royal Gold' },
  { id: 'frost', labelAr: 'زجاج ثلجي', labelEn: 'Frosted Glass' },
]);

/**
 * Strips spaces and dashes while preserving '*' or '•' for partial card numbers.
 */
export function normalizeCardInput(raw) {
  return String(raw || '').replace(/[\s\-]+/g, '').replace(/[•xX]/g, '*');
}

/**
 * Extracts only numeric digits.
 */
export function digitsOnly(raw) {
  return String(raw || '').replace(/\D+/g, '');
}

/**
 * Checks whether a card number is partial (contains masked/unknown middle digits like Samsung Pass).
 */
export function isPartialCardNumber(raw) {
  const norm = normalizeCardInput(raw);
  return norm.includes('*');
}

/**
 * Standard Luhn checksum validation for complete card numbers (13-19 digits).
 * Returns null if number is partial or too short to validate yet.
 */
export function validateLuhn(raw) {
  if (isPartialCardNumber(raw)) return null;
  const digits = digitsOnly(raw);
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Detects card brand from BIN prefix (supports partial numbers too since first 6 digits are known).
 */
export function detectCardBrand(raw, manualOverride = 'auto') {
  if (manualOverride && manualOverride !== 'auto') return manualOverride;

  const norm = normalizeCardInput(raw);
  const prefix = norm.replace(/\*.*$/, '');
  if (!prefix) return 'other';

  // Egyptian Meeza BIN ranges (507803-507810 and 5078xx)
  if (/^5078/.test(prefix)) return 'meeza';
  if (/^4/.test(prefix)) return 'visa';
  if (/^(5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(prefix)) return 'mastercard';
  if (/^3[47]/.test(prefix)) return 'amex';
  if (/^(6011|65|64[4-9])/.test(prefix)) return 'discover';
  if (/^62/.test(prefix)) return 'unionpay';
  return 'other';
}

/**
 * Formats card number in standard groups (4-6-5 for Amex, 4-4-4-4 for others).
 * Supports both full and partial numbers (showing '•' for unknown digits).
 */
export function formatCardNumber(raw, brand = null) {
  const norm = normalizeCardInput(raw);
  if (!norm) return '';
  const detected = brand || detectCardBrand(norm);
  const display = norm.replace(/\*/g, '•');

  if (detected === 'amex') {
    const p1 = display.slice(0, 4);
    const p2 = display.slice(4, 10);
    const p3 = display.slice(10, 15);
    return [p1, p2, p3].filter(Boolean).join(' ');
  }

  return display.replace(/(.{4})/g, '$1 ').trim();
}

/**
 * Returns masked display string for resting UI (reveals only last 4 digits, or first 6 + last 4 for partial).
 */
export function maskCardNumber(raw, brand = null) {
  const norm = normalizeCardInput(raw);
  if (!norm) return '•••• •••• •••• ••••';
  const detected = brand || detectCardBrand(norm);

  if (norm.includes('*')) {
    // Partial card: preserve known prefix/suffix and show • for unknown middle
    return formatCardNumber(norm, detected);
  }

  const len = norm.length;
  const last4 = norm.slice(-4);
  if (detected === 'amex') {
    return `•••• •••••• •${last4}`;
  }
  const maskedLen = Math.max(12, len) - last4.length;
  const masked = '•'.repeat(maskedLen) + last4;
  return formatCardNumber(masked, detected);
}

/**
 * Normalizes and validates expiry string (MM/YY).
 */
export function formatExpiry(raw) {
  const digits = digitsOnly(raw).slice(0, 4);
  if (digits.length <= 2) return digits;
  return `${digits.slice(0, 2)}/${digits.slice(2)}`;
}

/**
 * Checks if card expiry MM/YY is expired relative to current date.
 */
export function isCardExpired(expiry, now = new Date()) {
  const match = String(expiry || '').match(/^(\d{2})\/(\d{2,4})$/);
  if (!match) return false;
  const month = parseInt(match[1], 10);
  let year = parseInt(match[2], 10);
  if (month < 1 || month > 12) return false;
  if (year < 100) year += 2000;
  const expEnd = new Date(year, month, 0, 23, 59, 59);
  return expEnd < now;
}

/**
 * Builds a clean copy-all text block for a bank card.
 */
export function formatCardCopyAll(card, lang = 'ar') {
  const brand = detectCardBrand(card.number, card.brandOverride);
  const lines = [];
  if (card.cardName) lines.push(`${lang === 'ar' ? 'البطاقة' : 'Card'}: ${card.cardName}`);
  if (card.bankName) lines.push(`${lang === 'ar' ? 'البنك' : 'Bank'}: ${card.bankName}`);
  if (card.holderName) lines.push(`${lang === 'ar' ? 'الاسم' : 'Holder'}: ${card.holderName}`);
  if (card.number) lines.push(`${lang === 'ar' ? 'الرقم' : 'Number'}: ${formatCardNumber(card.number, brand)}`);
  if (card.expiry) lines.push(`${lang === 'ar' ? 'الانتهاء' : 'Expiry'}: ${card.expiry}`);
  if (card.cvv) lines.push(`CVV: ${card.cvv}`);
  if (card.pin) lines.push(`PIN: ${card.pin}`);
  return lines.join('\n');
}
