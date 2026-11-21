/**
 * Khazna (خزنة) — Zero-Server End-to-End Encrypted Device-to-Device Sync Engine
 *
 * SECURITY ARCHITECTURE:
 * - Zero cloud servers, zero external requests.
 * - Compresses sync payload with native gzip (CompressionStream) when available,
 *   then encrypts with PBKDF2-HMAC-SHA-256 (600,000 iterations, fresh 16-byte salt)
 *   + AES-256-GCM (fresh 96-bit IV) + AAD binding (`khazna:sync:v1|comp=<gzip|raw>`).
 * - Compact binary wire format:
 *     [4B magic "KZS\x01"] [1B flags] [16B salt] [12B iv] [ciphertext + 16B GCM tag]
 *   encoded as URL-safe Base64URL:
 *     - Sync Code: `KHAZNA-SYNC-1:<base64url>`
 *     - One-Tap Link: `<origin><pathname>#sync=<base64url>`
 * - Fragment (`#sync=...`) is NEVER sent over HTTP to any server, contains ZERO plaintext
 *   and ZERO decryption key, and is scrubbed from `window.location` immediately on load.
 */

import { derivePbkdf2Sha256 } from '../crypto/kdf.js';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  KhaznaError,
  randomBytes,
  randomId,
  utf8Decode,
  utf8Encode,
  zeroize,
} from '../crypto/utils.js';

export const SYNC_PREFIX = 'KHAZNA-SYNC-1:';
export const SYNC_HASH_KEY = 'sync=';
export const SYNC_PBKDF2_ITERATIONS = 600000;
export const SYNC_MAX_SAFE_URL_CHARS = 24000;

const SYNC_MAGIC = new Uint8Array([0x4b, 0x5a, 0x53, 0x01]); // "KZS\x01"
const FLAG_GZIP = 0x01;

async function tryGzipCompress(bytes) {
  if (typeof CompressionStream !== 'function') {
    return { bytes, compressed: false };
  }
  try {
    const cs = new CompressionStream('gzip');
    const writer = cs.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const out = new Uint8Array(await new Response(cs.readable).arrayBuffer());
    if (out.length < bytes.length) {
      return { bytes: out, compressed: true };
    }
    return { bytes, compressed: false };
  } catch {
    return { bytes, compressed: false };
  }
}

async function tryGzipDecompress(bytes) {
  if (typeof DecompressionStream !== 'function') {
    throw new KhaznaError(
      'SYNC_DECOMPRESS_UNSUPPORTED',
      'المتصفح الحالي لا يدعم فك ضغط gzip لحزمة المزامنة.',
      'This browser does not support gzip decompression for sync payloads.'
    );
  }
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}

function buildSyncAad(compressed) {
  return utf8Encode(`khazna:sync:v1|comp=${compressed ? 'gzip' : 'raw'}`);
}

/**
 * Selects either all vault records ('full') or only records updated after `sinceIso` ('delta').
 */
export function selectSyncRecords({
  sections = [],
  passwords = [],
  cards = [],
  notes = [],
  mode = 'delta',
  sinceIso = null,
}) {
  const cutoffMs = mode === 'delta' && sinceIso ? Date.parse(sinceIso) : 0;
  const isIncluded = (rec) => {
    if (!cutoffMs || Number.isNaN(cutoffMs)) return true;
    const ts = Date.parse(rec.updatedAt || rec.createdAt || '');
    return Number.isNaN(ts) || ts >= cutoffMs;
  };

  const selPasswords = passwords.filter((p) => !p.deletedAt && isIncluded(p));
  const selCards = cards.filter((c) => !c.deletedAt && isIncluded(c));
  const selNotes = notes.filter((n) => !n.deletedAt && isIncluded(n));

  // Always include referenced sections (or updated sections) so categories stay intact on target device
  const referencedSecIds = new Set(selPasswords.map((p) => p.data?.sectionId).filter(Boolean));
  const selSections = sections.filter(
    (s) => !s.deletedAt && (mode === 'full' || isIncluded(s) || referencedSecIds.has(s.id))
  );

  return {
    v: 1,
    mode,
    since: mode === 'delta' ? sinceIso : null,
    exportedAt: new Date().toISOString(),
    sections: selSections.map((s) => ({
      id: s.id,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
      data: s.data,
    })),
    passwords: selPasswords.map((p) => ({
      id: p.id,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
      data: p.data,
    })),
    cards: selCards.map((c) => ({
      id: c.id,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
      data: c.data,
    })),
    notes: selNotes.map((n) => ({
      id: n.id,
      createdAt: n.createdAt,
      updatedAt: n.updatedAt,
      data: n.data,
    })),
  };
}

/**
 * Encrypts a sync payload into a compact URL-safe token (`KHAZNA-SYNC-1:<b64url>`).
 */
export async function encodeSyncPackage({
  payload,
  passphrase,
  iterations = SYNC_PBKDF2_ITERATIONS,
  useCompression = true,
}) {
  if (!passphrase || String(passphrase).length < 4) {
    throw new KhaznaError(
      'SYNC_PASS_TOO_SHORT',
      'يجب إدخال كلمة مرور للمزامنة (٤ أحرف على الأقل، ويُفضّل استخدام كلمة مرور قوية).',
      'Enter a sync passphrase (at least 4 characters; a strong passphrase is recommended).'
    );
  }

  const rawJson = utf8Encode(JSON.stringify(payload));
  const { bytes: bodyBytes, compressed } = useCompression
    ? await tryGzipCompress(rawJson)
    : { bytes: rawJson, compressed: false };

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const pwdBytes = utf8Encode(String(passphrase));
  let keyBytes = null;

  try {
    keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, iterations, 32);
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const aad = buildSyncAad(compressed);
    const ctBuf = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      aesKey,
      bodyBytes
    );

    const flags = new Uint8Array([compressed ? FLAG_GZIP : 0]);
    const packet = concatBytes(SYNC_MAGIC, flags, salt, iv, new Uint8Array(ctBuf));
    const token = bytesToBase64Url(packet);
    const code = `${SYNC_PREFIX}${token}`;

    return {
      code,
      token,
      compressed,
      byteLength: packet.length,
      counts: {
        sections: payload.sections?.length || 0,
        passwords: payload.passwords?.length || 0,
        cards: payload.cards?.length || 0,
        notes: payload.notes?.length || 0,
      },
    };
  } finally {
    zeroize(pwdBytes, rawJson, bodyBytes, keyBytes);
  }
}

/**
 * Extracts raw Base64URL sync token from:
 * - A full sync URL (`https://example.com/#sync=<token>`)
 * - A raw hash fragment (`#sync=<token>` or `sync=<token>`)
 * - A sync code (`KHAZNA-SYNC-1:<token>`)
 * - A raw Base64URL token
 */
export function extractSyncTokenFromInput(input) {
  const trimmed = String(input || '').trim();
  if (!trimmed) return '';

  // URL or hash fragment containing #sync= or sync=
  const hashIdx = trimmed.indexOf('#');
  if (hashIdx !== -1) {
    const frag = trimmed.slice(hashIdx + 1);
    const params = new URLSearchParams(frag);
    const fromParam = params.get('sync');
    if (fromParam) return fromParam.replace(/\s+/g, '');
  }
  if (trimmed.startsWith(SYNC_HASH_KEY)) {
    return trimmed.slice(SYNC_HASH_KEY.length).replace(/\s+/g, '');
  }
  if (trimmed.toUpperCase().startsWith(SYNC_PREFIX)) {
    return trimmed.slice(SYNC_PREFIX.length).replace(/\s+/g, '');
  }
  return trimmed.replace(/\s+/g, '');
}

/**
 * Builds a clickable one-tap sync link using ONLY the URL hash fragment (`#sync=...`)
 * so the encrypted ciphertext is NEVER sent to any web server in HTTP requests.
 */
export function buildSyncLink(baseUrl, token) {
  const cleanBase = String(baseUrl || '').split('#')[0].split('?')[0];
  const url = `${cleanBase}#sync=${token}`;
  return {
    url,
    length: url.length,
    fitsUrl: url.length <= SYNC_MAX_SAFE_URL_CHARS,
  };
}

/**
 * Decrypts and authenticates a sync code/link back into the payload object.
 */
export async function decodeSyncPackage({
  input,
  passphrase,
  iterations = SYNC_PBKDF2_ITERATIONS,
}) {
  const token = extractSyncTokenFromInput(input);
  if (!token) {
    throw new KhaznaError(
      'SYNC_EMPTY',
      'يرجى لصق كود أو رابط المزامنة المشفّر أولاً.',
      'Please paste an encrypted sync code or link first.'
    );
  }
  if (!passphrase) {
    throw new KhaznaError(
      'SYNC_PASS_REQUIRED',
      'يرجى إدخال كلمة مرور المزامنة لفك التشفير.',
      'Please enter the sync passphrase to decrypt.'
    );
  }

  let packet;
  try {
    packet = base64UrlToBytes(token);
  } catch {
    throw new KhaznaError(
      'SYNC_INVALID_FORMAT',
      'تنسيق كود المزامنة غير صالح أو ناقص.',
      'Sync code format is invalid or truncated.'
    );
  }

  if (
    packet.length < 4 + 1 + 16 + 12 + 16 ||
    packet[0] !== SYNC_MAGIC[0] ||
    packet[1] !== SYNC_MAGIC[1] ||
    packet[2] !== SYNC_MAGIC[2] ||
    packet[3] !== SYNC_MAGIC[3]
  ) {
    throw new KhaznaError(
      'SYNC_INVALID_MAGIC',
      'هذا الكود ليس حزمة مزامنة صالحة من خزنة.',
      'This code is not a valid Khazna sync package.'
    );
  }

  const flags = packet[4];
  const compressed = Boolean(flags & FLAG_GZIP);
  const salt = packet.subarray(5, 21);
  const iv = packet.subarray(21, 33);
  const ciphertext = packet.subarray(33);

  const pwdBytes = utf8Encode(String(passphrase));
  let keyBytes = null;
  let plainBytes = null;

  try {
    keyBytes = await derivePbkdf2Sha256(pwdBytes, salt, iterations, 32);
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const aad = buildSyncAad(compressed);
    let decryptedBuf;
    try {
      decryptedBuf = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext
      );
    } catch {
      throw new KhaznaError(
        'SYNC_DECRYPT_FAILED',
        'كلمة مرور المزامنة غير صحيحة أو تم التلاعب بالكود.',
        'Incorrect sync passphrase or tampered sync code.'
      );
    }

    plainBytes = compressed
      ? await tryGzipDecompress(new Uint8Array(decryptedBuf))
      : new Uint8Array(decryptedBuf);

    const parsed = JSON.parse(utf8Decode(plainBytes));
    if (!parsed || parsed.v !== 1) {
      throw new KhaznaError(
        'SYNC_UNSUPPORTED_VERSION',
        'إصدار حزمة المزامنة غير مدعوم.',
        'Unsupported sync package version.'
      );
    }
    return parsed;
  } finally {
    zeroize(pwdBytes, keyBytes, plainBytes);
  }
}

// --- Smart Conflict-Safe Merge Planner ---

function normText(v) {
  return String(v || '').trim().toLowerCase();
}

function naturalKey(type, data = {}) {
  if (type === 'section') return `sec:${normText(data.name)}`;
  if (type === 'password') return `pwd:${normText(data.title)}|${normText(data.username)}|${normText(data.url)}`;
  if (type === 'card') {
    const digits = String(data.number || '').replace(/\D/g, '');
    const last4 = digits.slice(-4) || String(data.last4 || '');
    return `crd:${normText(data.title)}|${last4}`;
  }
  if (type === 'note') return `not:${normText(data.title)}`;
  return '';
}

function stableDataEquals(a, b) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

function parseTs(iso) {
  const n = Date.parse(iso || '');
  return Number.isNaN(n) ? 0 : n;
}

/**
 * Pure conflict-safe merge planner:
 * - Matches by record `id` first, then by natural key so cross-device entries never duplicate.
 * - `strategy = 'smart'` (default): newer `updatedAt` wins; older remote NEVER overwrites newer local.
 * - `strategy = 'add-only'`: only inserts missing items; never modifies existing local records.
 * - Never deletes untouched local items.
 */
export function planSyncMerge({
  incoming,
  localSections = [],
  localPasswords = [],
  localCards = [],
  localNotes = [],
  strategy = 'smart', // 'smart' | 'add-only'
}) {
  const sectionIdMap = new Map();
  const sectionActions = [];

  const localSecById = new Map(localSections.map((s) => [s.id, s]));
  const localSecByKey = new Map(localSections.map((s) => [naturalKey('section', s.data), s]));

  for (const inc of incoming.sections || []) {
    const match = localSecById.get(inc.id) || localSecByKey.get(naturalKey('section', inc.data));
    if (!match) {
      const newId = inc.id || randomId('sec');
      sectionIdMap.set(inc.id, newId);
      sectionActions.push({ action: 'add', id: newId, data: inc.data, updatedAt: inc.updatedAt });
    } else {
      sectionIdMap.set(inc.id, match.id);
      if (
        strategy === 'smart' &&
        parseTs(inc.updatedAt) > parseTs(match.updatedAt) &&
        !stableDataEquals(inc.data, match.data)
      ) {
        sectionActions.push({ action: 'update', id: match.id, data: inc.data, updatedAt: inc.updatedAt });
      } else {
        sectionActions.push({ action: 'unchanged', id: match.id });
      }
    }
  }

  const planType = (type, incList, localList, transformData = (d) => d) => {
    const byId = new Map(localList.map((r) => [r.id, r]));
    const byKey = new Map(localList.map((r) => [naturalKey(type, r.data), r]));
    const actions = [];

    for (const inc of incList || []) {
      const data = transformData(inc.data || {});
      const key = naturalKey(type, data);
      const match = byId.get(inc.id) || (key ? byKey.get(key) : null);

      if (!match) {
        actions.push({
          action: 'add',
          id: inc.id || randomId(type.slice(0, 3)),
          data,
          createdAt: inc.createdAt,
          updatedAt: inc.updatedAt,
        });
      } else if (
        strategy === 'smart' &&
        parseTs(inc.updatedAt) > parseTs(match.updatedAt) &&
        !stableDataEquals(data, match.data)
      ) {
        actions.push({
          action: 'update',
          id: match.id,
          data,
          createdAt: match.createdAt,
          updatedAt: inc.updatedAt,
        });
      } else {
        actions.push({ action: 'unchanged', id: match.id });
      }
    }
    return actions;
  };

  const passwordActions = planType('password', incoming.passwords, localPasswords, (d) => ({
    ...d,
    sectionId: d.sectionId ? (sectionIdMap.get(d.sectionId) || d.sectionId) : null,
  }));
  const cardActions = planType('card', incoming.cards, localCards);
  const noteActions = planType('note', incoming.notes, localNotes);

  const count = (arr, kind) => arr.filter((x) => x.action === kind).length;

  return {
    mode: incoming.mode || 'full',
    exportedAt: incoming.exportedAt || null,
    sections: sectionActions,
    passwords: passwordActions,
    cards: cardActions,
    notes: noteActions,
    summary: {
      added:
        count(sectionActions, 'add') +
        count(passwordActions, 'add') +
        count(cardActions, 'add') +
        count(noteActions, 'add'),
      updated:
        count(sectionActions, 'update') +
        count(passwordActions, 'update') +
        count(cardActions, 'update') +
        count(noteActions, 'update'),
      unchanged:
        count(sectionActions, 'unchanged') +
        count(passwordActions, 'unchanged') +
        count(cardActions, 'unchanged') +
        count(noteActions, 'unchanged'),
      passwordsAdded: count(passwordActions, 'add'),
      passwordsUpdated: count(passwordActions, 'update'),
      cardsAdded: count(cardActions, 'add'),
      cardsUpdated: count(cardActions, 'update'),
      notesAdded: count(noteActions, 'add'),
      notesUpdated: count(noteActions, 'update'),
    },
  };
}

/**
 * Applies a planned sync merge atomically, first saving a rolling encrypted snapshot
 * so the user can always undo from Settings.
 */
export async function applySyncMerge({ session, plan }) {
  const itemsToEncrypt = [];
  for (const s of plan.sections) {
    if (s.action === 'add' || s.action === 'update') {
      itemsToEncrypt.push({ type: 'section', id: s.id, data: s.data, createdAt: s.createdAt });
    }
  }
  for (const p of plan.passwords) {
    if (p.action === 'add' || p.action === 'update') {
      itemsToEncrypt.push({ type: 'password', id: p.id, data: p.data, createdAt: p.createdAt });
    }
  }
  for (const c of plan.cards) {
    if (c.action === 'add' || c.action === 'update') {
      itemsToEncrypt.push({ type: 'card', id: c.id, data: c.data, createdAt: c.createdAt });
    }
  }
  for (const n of plan.notes) {
    if (n.action === 'add' || n.action === 'update') {
      itemsToEncrypt.push({ type: 'note', id: n.id, data: n.data, createdAt: n.createdAt });
    }
  }

  let snapshotId = null;
  if (itemsToEncrypt.length > 0) {
    const encryptedBatch = await session.encryptBatchForAtomicWrite(itemsToEncrypt);
    snapshotId = await session.storage.atomicOperationWithSnapshot({
      reason: 'device-sync',
      putRecords: encryptedBatch,
    });
  }

  await session.updateSettings({ lastSyncAt: new Date().toISOString() });

  return {
    snapshotId,
    appliedCount: itemsToEncrypt.length,
    summary: plan.summary,
  };
}
