/**
 * Optional Local Argon2id WASM Hook (Zero External Requests)
 *
 * By default, Khazna uses its built-in RFC 9106 pure-JS Argon2id engine inside a Web Worker
 * (verified byte-for-byte against the RFC 9106 §5.3 test vector).
 *
 * To optionally accelerate Argon2id with a locally vendored WASM module (e.g. hash-wasm),
 * replace this file with the verified local ESM bundle exporting `argon2id`, record its SHA-256
 * in README.md, and run `npm run integrity`.
 */

export const argon2id = null;
