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

  /* NCALayer (pki.gov.kz) listens on the user's computer. The "basics" module is the current API; older
     installations only have commonUtils, so the call falls back to it. "sign" keys (RSA/GOST) sign documents,
     "auth" keys sign the login challenge. */
  var NCALAYER = "wss://127.0.0.1:13579/";
  var OIDS = { sign: "1.3.6.1.5.5.7.3.4", auth: "1.3.6.1.5.5.7.3.2" };
  var me = document.currentScript || document.querySelector('script[src*="/static/js/eds.js"]');
  var NOLAYER = (me && me.getAttribute("data-nolayer")) || "NCALayer is not running.";
  var INSTALL = (me && me.getAttribute("data-install")) || "Install NCALayer";

  function ncalayerCall(payload) {
    return new Promise(function (resolve, reject) {
      var ws, done = false;
      var fail = function (e) { if (!done) { done = true; reject(e); } };
      try { ws = new WebSocket(NCALAYER); } catch (e) { var err = new Error(NOLAYER); err.nolayer = true; fail(err); return; }
      ws.onerror = function () { var err = new Error(NOLAYER); err.nolayer = true; fail(err); };
      ws.onclose = function () { fail(new Error("signing cancelled")); };
      ws.onopen = function () { ws.send(JSON.stringify(payload)); };
      ws.onmessage = function (m) {
        var r;
        try { r = JSON.parse(m.data); } catch (e) { return; }
        if (r && r.result && r.result.version) return;  // version banner sent on connect
        done = true;
        ws.close();
        resolve(r || {});
      };
    });
  }

  function ncalayerSign(data, key) {
    key = key === "auth" ? "auth" : "sign";
    var payload = b64(data);
    return ncalayerCall({
      module: "kz.gov.pki.knca.basics", method: "sign",
      args: { allowedStorages: ["PKCS12", "AKKaztokenStore", "AKKZIDCardStore", "AKJaCartaStore"], format: "cms",
              data: payload, signingParams: { decode: true, encapsulate: false, digested: false, tsaProfile: {} },
              signerParams: { extKeyUsageOids: [OIDS[key]], chain: [] }, locale: document.documentElement.lang || "ru" }
    }).then(function (r) {
      if (r.status === true && r.body && r.body.result) return Array.isArray(r.body.result) ? r.body.result[0] : r.body.result;
      if (r.status === undefined && r.code !== undefined) {
        return ncalayerCall({ module: "kz.gov.pki.knca.commonUtils", method: "createCMSSignatureFromBase64",
                              args: ["PKCS12", key === "auth" ? "AUTHENTICATION" : "SIGNATURE", payload, false] })
          .then(function (o) {
            if (String(o.code) === "200" && o.responseObject) return o.responseObject;
            throw new Error(o.message || "signing cancelled");
          });
      }
      throw new Error(r.message || (r.body && r.body.message) || "signing cancelled");
    });
  }

  /* a failure message; when NCALayer is not running, a link to install it */
  function showError(status, prefix, e) {
    if (!status) return;
    status.textContent = prefix + " " + (e && e.message ? e.message : "");
    if (e && e.nolayer) {
      var a = document.createElement("a");
      a.href = "https://pki.gov.kz/ncalayer/";
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = INSTALL;
      status.appendChild(document.createTextNode(" "));
      status.appendChild(a);
    }
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

  function devKeySign(text, certUrl, slot) {
    slot = slot || "default";
    var subtle = window.crypto && window.crypto.subtle, data = new TextEncoder().encode(text);
    if (!subtle || !window.indexedDB) return Promise.reject(new Error("WebCrypto is not available"));
    var made = certUrl ? subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
      .then(function (k) {
        return subtle.exportKey("spki", k.publicKey).then(function (spki) {
          return post(certUrl, "public_key=" + encodeURIComponent(b64(spki)));
        }).then(function (r) { if (!r.ok) throw new Error("certificate"); return r.json(); })
          .then(function (j) {
            var rec = { key: k.privateKey, cert: j.certificate };
            return idb("readwrite", function (st) { return st.put(rec, slot); }).then(function () { return rec; });
          });
      }) : idb("readonly", function (st) { return st.get(slot); });
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
          if (dev) return devKeySign(c, btn.getAttribute("data-cert"), btn.getAttribute("data-slot"));
          return ncalayerSign(new TextEncoder().encode(c), btn.getAttribute("data-key"));
        })
        .then(function (pkg) {
          var next = btn.getAttribute("data-next") || "";
          return post(btn.getAttribute("data-action"), "package=" + encodeURIComponent(pkg) +
            "&challenge=" + encodeURIComponent(text) + "&next=" + encodeURIComponent(next));
        })
        .then(function (r) { window.location.href = r.url || window.location.href; })
        .catch(function (e) { btn.disabled = false; showError(status, btn.getAttribute("data-fail"), e); });
    });
  });

  /* ---- eGov mobile / eGov Business: QR for the app, the browser waits for the result. Used for login
     (FR-AUTH-09) and for signing a deal document (FR-DOC-07). */
  function bytesOf(b64text) {
    var bin = atob(b64text), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  document.querySelectorAll("[data-egov]").forEach(function (egov) {
    var estatus = egov.querySelector("[data-egov-status]"), started = null, timer = null;
    var esay = function (t) { if (estatus) estatus.textContent = t; };
    var check = function () {
      fetch(started.status, { credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error("expired"); return r.json(); })
        .then(function (j) {
          if (j.status === "signed") { clearInterval(timer); window.location.href = j.redirect || "/dashboard"; }
          else if (j.status === "failed") { clearInterval(timer); esay(egov.getAttribute("data-fail") + " " + (j.message || "")); }
        }).catch(function () { clearInterval(timer); esay(egov.getAttribute("data-expired")); });
    };
    egov.querySelector("[data-egov-start]").addEventListener("click", function () {
      post(egov.getAttribute("data-start") || "/login/egov/start", "")
        .then(function (r) { if (!r.ok) throw new Error("start"); return r.json(); })
        .then(function (j) {
          started = j;
          egov.querySelector("[data-egov-qr]").src = j.qr;
          egov.querySelector("[data-egov-panel]").hidden = false;
          esay(egov.getAttribute("data-wait"));
          if (timer) clearInterval(timer);
          timer = setInterval(check, 2000);
          setTimeout(function () { if (timer) clearInterval(timer); }, 300000);  // attempts live 5 minutes
        }).catch(function (e) { esay(egov.getAttribute("data-fail") + " " + (e && e.message || "")); });
    });
    var phone = egov.querySelector("[data-egov-devphone]");
    if (phone) {
      // development only: this button plays the eGov mobile app with the browser's test key
      phone.addEventListener("click", function () {
        if (!started || !started.dev_api) return;
        var meta, certUrl = egov.getAttribute("data-cert");
        fetch(started.dev_api).then(function (r) { return r.json(); })
          .then(function (m) { meta = m; return fetch(m.document.uri.replace(/^https?:\/\/[^/]+/, ""),
                { headers: { "Authorization": "Bearer " + m.document.auth_token } }); })
          .then(function (r) { return r.json(); })
          .then(function (doc) {
            var file = doc.documentsToSign[0].document.file;
            var signing = certUrl ? devSign(bytesOf(file.data), certUrl)  // a document: sign its bytes
              : devKeySign(atob(file.data), null, "default");               // login: the challenge text
            return signing.then(function (pkg) {
              file.data = btoa(unescape(encodeURIComponent(pkg)));
              return fetch(meta.document.uri.replace(/^https?:\/\/[^/]+/, ""), { method: "PUT",
                headers: { "Content-Type": "application/json", "Authorization": "Bearer " + meta.document.auth_token },
                body: JSON.stringify(doc) });
            });
          }).catch(function (e) { esay(egov.getAttribute("data-fail") + " " + (e && e.message || "")); });
      });
    }
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
          return btn.getAttribute("data-mode") === "dev" ? devSign(data, btn.getAttribute("data-cert")) : ncalayerSign(data, "sign");
        })
        .then(function (pkg) {
          return fetch(btn.getAttribute("data-action"), { method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf },
            body: "package=" + encodeURIComponent(pkg) });
        })
        .then(function (r) { window.location.href = r.url || window.location.href; })
        .catch(function (e) { btn.disabled = false; showError(status, btn.getAttribute("data-fail"), e); });
    });
  });
})();
