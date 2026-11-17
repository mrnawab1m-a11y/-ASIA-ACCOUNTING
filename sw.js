/* Minimal service worker for iOS 16+ and modern browsers.
   Deliberately does not cache HTML, API responses, credentials, or financial data. */
self.addEventListener("install", event => {
  self.skipWaiting();
});
self.addEventListener("activate", event => {
  event.waitUntil(self.clients.claim());
});
