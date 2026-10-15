/* AbdEX service worker (FR-MOB-02): offline cache of the app shell and key driver screens.
   Personal data pages are never cached (network-only); only static assets and /trips shell. */
var CACHE = "abdex-v2";
var SHELL = ["/static/css/app.css?v=2", "/static/js/app.js?v=2", "/static/icons/icon.svg", "/static/icons/sprite.svg", "/manifest.webmanifest"];

self.addEventListener("install", function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }));
  self.skipWaiting();
});

self.addEventListener("activate", function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }));
  self.clients.claim();
});

self.addEventListener("fetch", function (e) {
  var url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  if (url.pathname.startsWith("/static/")) {
    // stale-while-revalidate: instant from cache, refreshed in the background
    e.respondWith(caches.open(CACHE).then(function (c) {
      return c.match(e.request).then(function (hit) {
        var net = fetch(e.request).then(function (resp) { if (resp.ok) c.put(e.request, resp.clone()); return resp; })
          .catch(function () { return hit; });
        return hit || net;
      });
    }));
    return;
  }
  if (url.pathname === "/trips") {
    e.respondWith(fetch(e.request).then(function (resp) {
      var copy = resp.clone();
      caches.open(CACHE).then(function (c) { c.put(e.request, copy); });
      return resp;
    }).catch(function () { return caches.match(e.request); }));
  }
});

self.addEventListener("push", function (e) {
  var data = {};
  try { data = e.data.json(); } catch (err) { data = { title: "AbdEX", body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(data.title || "AbdEX", { body: data.body || "", icon: "/static/icons/icon.svg",
    data: { url: data.url || "/notifications" } }));
});

self.addEventListener("notificationclick", function (e) {
  e.notification.close();
  e.waitUntil(self.clients.openWindow(e.notification.data.url));
});
