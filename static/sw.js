const CACHE_NAME = "arinex-jamb-static-v1";
const STATIC_FILES = [
  "/static/css/style.css",
  "/static/js/app.js",
  "/static/manifest.json",
  "/static/icons/icon.svg",
  "/static/offline.html"
];
self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_FILES)));
  self.skipWaiting();
});
self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))));
  self.clients.claim();
});
self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/static/")) {
    event.respondWith(caches.match(request).then((cached) => cached || fetch(request)));
    return;
  }
  // Authenticated pages, exam sessions, payments and submissions are never cached.
  if (url.pathname === "/" || url.pathname === "/rules") {
    event.respondWith(fetch(request).catch(() => caches.match("/static/offline.html")));
  }
});
