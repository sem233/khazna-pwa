/**
 * Khazna Extension Background Service Worker (Manifest V3)
 * Zero external connections — 100% local only.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('خزنة (Khazna) Chrome Extension v2.6.0 ready — 100% offline.');
});
