/**
 * Khazna Extension Background Service Worker
 * Zero external connections — 100% local only.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('خزنة Chrome Extension v2.0.0 installed successfully.');
});
