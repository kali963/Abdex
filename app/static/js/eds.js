/* Qualified e-signature in the browser (FR-DOC-07, GOV-DS-01, GOV-DS-06).
   The private key never leaves the user's device: NCALayer (NCA RK certificates) signs locally and returns a
   CMS; in development a WebCrypto key is generated in the browser and a test CA certifies its public key.
   The server verifies the result itself (GOV-DS-02). */
(function () {
  "use strict";
  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  function b64(buf) {
    var bin = "", bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function ncalayerSign(data) {
    return new Promise(function (resolve, reject) {
      var ws;
      try { ws = new WebSocket("wss://127.0.0.1:13579/"); } catch (e) { reject(e); return; }
      ws.onerror = function () { reject(new Error("NCALayer is not running")); };
      ws.onopen = function () {
        ws.send(JSON.stringify({
          module: "kz.gov.pki.knca.basics", method: "sign",
          args: { allowedStorages: ["PKCS12", "AKKaztokenStore", "AKKZIDCardStore", "AKJaCartaStore"], format: "cms",
                  data: b64(data), signingParams: { decode: true, encapsulate: false, digested: false, tsaProfile: {} },
                  signerParams: { extKeyUsageOids: ["1.3.6.1.5.5.7.3.4"] }, locale: "ru" }
        }));
      };
      ws.onmessage = function (m) {
        var r = JSON.parse(m.data);
        if (r.status === undefined) return;  // version banner
        ws.close();
        if (r.status && r.body && r.body.result) resolve(r.body.result[0] || r.body.result);
        else reject(new Error(r.message || "signing cancelled"));
      };
    });
  }

  function devSign(data, certUrl) {
    var subtle = window.crypto && window.crypto.subtle;
    if (!subtle) return Promise.reject(new Error("WebCrypto is not available"));
    var keys;
    return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
      .then(function (k) { keys = k; return subtle.exportKey("spki", k.publicKey); })
      .then(function (spki) {
        return fetch(certUrl, { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf },
          body: "public_key=" + encodeURIComponent(b64(spki)) });
      })
      .then(function (r) { if (!r.ok) throw new Error("certificate"); return r.json(); })
      .then(function (j) {
        return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, data)
          .then(function (sig) { return JSON.stringify({ cert: j.certificate, sig: b64(sig) }); });
      });
  }

  /* ---- FR-AUTH-09: EDS login. In development the browser keeps a non-extractable WebCrypto key and its test
     certificate in IndexedDB (a stand-in for the key store NCALayer reads in production). */
  var DB = "abdex-eds", STORE = "keys";

  function idb(mode, fn) {
    return new Promise(function (resolve, reject) {
      var open = indexedDB.open(DB, 1);
      open.onupgradeneeded = function () { open.result.createObjectStore(STORE); };
      open.onerror = function () { reject(open.error); };
      open.onsuccess = function () {
        var tx = open.result.transaction(STORE, mode), req = fn(tx.objectStore(STORE));
        tx.oncomplete = function () { resolve(req && req.result); };
        tx.onerror = function () { reject(tx.error); };
      };
    });
  }

  function post(url, body) {
    return fetch(url, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf }, body: body });
  }

  function challenge(url) {
    return post(url, "").then(function (r) { if (!r.ok) throw new Error("challenge"); return r.json(); })
      .then(function (j) { return j.challenge; });
  }

  function devKeySign(text, certUrl) {
    var subtle = window.crypto && window.crypto.subtle, data = new TextEncoder().encode(text);
    if (!subtle || !window.indexedDB) return Promise.reject(new Error("WebCrypto is not available"));
    var made = certUrl ? subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
      .then(function (k) {
        return subtle.exportKey("spki", k.publicKey).then(function (spki) {
          return post(certUrl, "public_key=" + encodeURIComponent(b64(spki)));
        }).then(function (r) { if (!r.ok) throw new Error("certificate"); return r.json(); })
          .then(function (j) {
            var rec = { key: k.privateKey, cert: j.certificate };
            return idb("readwrite", function (st) { return st.put(rec, "default"); }).then(function () { return rec; });
          });
      }) : idb("readonly", function (st) { return st.get("default"); });
    return made.then(function (rec) {
      if (!rec) throw new Error("no key");
      return subtle.sign({ name: "ECDSA", hash: "SHA-256" }, rec.key, data)
        .then(function (sig) { return JSON.stringify({ cert: rec.cert, sig: b64(sig) }); });
    });
  }

  document.querySelectorAll("[data-eds-auth]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var status = btn.parentNode.querySelector("[data-eds-status]");
      var say = function (t) { if (status) status.textContent = t; };
      var dev = btn.getAttribute("data-mode") === "dev", text;
      btn.disabled = true;
      say(btn.getAttribute("data-wait"));
      challenge(btn.getAttribute("data-challenge"))
        .then(function (c) {
          text = c;
          if (dev) return devKeySign(c, btn.getAttribute("data-cert"));
          return ncalayerSign(new TextEncoder().encode(c));
        })
        .then(function (pkg) {
          var next = btn.getAttribute("data-next") || "";
          return post(btn.getAttribute("data-action"), "package=" + encodeURIComponent(pkg) +
            "&challenge=" + encodeURIComponent(text) + "&next=" + encodeURIComponent(next));
        })
        .then(function (r) { window.location.href = r.url || window.location.href; })
        .catch(function (e) { btn.disabled = false; say(btn.getAttribute("data-fail") + " " + (e && e.message ? e.message : "")); });
    });
  });

  document.querySelectorAll("[data-eds-sign]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var status = btn.parentNode.querySelector("[data-eds-status]");
      var say = function (t) { if (status) status.textContent = t; };
      btn.disabled = true;
      say(btn.getAttribute("data-wait"));
      fetch(btn.getAttribute("data-file"), { credentials: "same-origin" })
        .then(function (r) { if (!r.ok) throw new Error("document"); return r.arrayBuffer(); })
        .then(function (data) {
          return btn.getAttribute("data-mode") === "dev" ? devSign(data, btn.getAttribute("data-cert")) : ncalayerSign(data);
        })
        .then(function (pkg) {
          return fetch(btn.getAttribute("data-action"), { method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf },
            body: "package=" + encodeURIComponent(pkg) });
        })
        .then(function (r) { window.location.href = r.url || window.location.href; })
        .catch(function (e) { btn.disabled = false; say(btn.getAttribute("data-fail") + " " + (e && e.message ? e.message : "")); });
    });
  });
})();
