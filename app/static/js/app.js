/* AbdEX progressive enhancement. The site works without JS; this adds convenience only.
   No inline scripts are used anywhere (CSP script-src 'self'). */
(function () {
  "use strict";

  var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  // ---- logout wipes the offline cache (driver trips) so the next person on a shared phone sees nothing
  document.querySelectorAll('form[action="/logout"]').forEach(function (f) {
    f.addEventListener("submit", function () {
      try { localStorage.removeItem("abdex-checkpoints"); } catch (e) { /* ignore */ }
      if (window.caches) caches.keys().then(function (ks) { ks.forEach(function (k) { caches.delete(k); }); });
    });
  });

  // ---- confirmations ------------------------------------------------------------------
  document.addEventListener("submit", function (e) {
    var f = e.target;
    var msg = f.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { e.preventDefault(); return; }
    // prevent double submit (NFR-FE-07); the server is idempotent anyway
    var btns = f.querySelectorAll("button[type=submit]");
    setTimeout(function () { btns.forEach(function (b) { b.disabled = true; }); }, 0);
    setTimeout(function () { btns.forEach(function (b) { b.disabled = false; }); }, 6000);
  });

  // ---- auto-submit selects (company switcher, filters) --------------------------------
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  // ---- route points: add / remove -----------------------------------------------------
  var points = document.querySelector("[data-points]");
  if (points) {
    var tpl = document.getElementById("point-template");
    document.querySelector("[data-add-point]").addEventListener("click", function () {
      var node = tpl.content.cloneNode(true);
      var all = points.querySelectorAll(".point");
      points.insertBefore(node, all[all.length - 1]);
    });
    points.addEventListener("click", function (e) {
      if (e.target.matches("[data-remove-point]")) {
        if (points.querySelectorAll(".point").length > 2) e.target.closest(".point").remove();
      }
    });
  }

  // ---- keep long form drafts when the connection drops (NFR-FE-07) -------------------
  var draftForm = document.querySelector("form[data-draft]");
  if (draftForm) {
    var key = "abdex-draft:" + draftForm.getAttribute("data-draft");
    var restoreBtn = document.querySelector("[data-restore-draft]");
    try {
      var saved = localStorage.getItem(key);
      if (saved && restoreBtn) {
        restoreBtn.hidden = false;
        restoreBtn.addEventListener("click", function () {
          var data = JSON.parse(saved);
          Object.keys(data).forEach(function (name) {
            var el = draftForm.elements[name];
            if (!el || el.length) return;
            if (el.type === "checkbox") el.checked = !!data[name]; else el.value = data[name];
          });
          restoreBtn.hidden = true;
        });
      }
    } catch (err) { /* storage unavailable */ }
    draftForm.addEventListener("input", function () {
      var data = {};
      Array.prototype.forEach.call(draftForm.elements, function (el) {
        if (!el.name || el.type === "hidden" || el.type === "password" || el.type === "file") return;
        if (draftForm.elements[el.name].length) return;
        data[el.name] = el.type === "checkbox" ? el.checked : el.value;
      });
      try { localStorage.setItem(key, JSON.stringify(data)); } catch (err) { /* ignore */ }
    });
    draftForm.addEventListener("submit", function () {
      try { localStorage.removeItem(key); } catch (err) { /* ignore */ }
    });
  }

  // ---- geolocation for checkpoints (only when the deal has geo consent) -------------
  document.querySelectorAll("form[data-geo]").forEach(function (f) {
    if (!navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition(function (pos) {
      f.querySelector("[name=lat]").value = pos.coords.latitude.toFixed(6);
      f.querySelector("[name=lng]").value = pos.coords.longitude.toFixed(6);
    }, function () { /* denied: checkpoint is still saved without coordinates */ }, { timeout: 8000, maximumAge: 60000 });
  });

  // ---- offline checkpoints queue (FR-TRK-07) -------------------------------------------
  var QKEY = "abdex-checkpoints";
  function queue() { try { return JSON.parse(localStorage.getItem(QKEY) || "[]"); } catch (e) { return []; } }
  function saveQueue(q) { try { localStorage.setItem(QKEY, JSON.stringify(q)); } catch (e) { /* ignore */ } }
  function flush() {
    var q = queue();
    if (!q.length || !navigator.onLine) return;
    var item = q[0];
    var body = new URLSearchParams(item.data);
    fetch(item.url, { method: "POST", credentials: "same-origin",
      headers: { "Accept": "application/json", "X-CSRF-Token": csrf }, body: body })
      .then(function (r) { if (r.ok || r.status === 409) { q.shift(); saveQueue(q); flush(); } })
      .catch(function () { /* retry later */ });
  }
  document.querySelectorAll("form[data-offline]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (navigator.onLine) return;
      e.preventDefault();
      var data = {};
      new FormData(f).forEach(function (v, k) { if (typeof v === "string") data[k] = v; });
      var q = queue(); q.push({ url: f.action, data: data }); saveQueue(q);
      alert(f.getAttribute("data-offline"));
    });
  });
  window.addEventListener("online", function () { document.body.classList.remove("offline"); flush(); });
  window.addEventListener("offline", function () { document.body.classList.add("offline"); });
  if (!navigator.onLine) document.body.classList.add("offline");
  flush();

  // ---- deal chat (FR-CHAT-06): WebSocket, falling back to polling; sent ✓ / read ✓✓ ----------
  var chat = document.querySelector("[data-chat]");
  if (chat) {
    var url = chat.getAttribute("data-chat");
    var last = chat.getAttribute("data-last") || "";
    var timer = null, socket = null;
    var render = function (m) {
      if (document.getElementById("m-" + m.id)) return;
      var div = document.createElement("div");
      div.id = "m-" + m.id;
      div.className = "msg " + (m.kind === "system" ? "system" : (m.mine ? "mine" : ""));
      div.appendChild(document.createTextNode(m.text));
      if (m.file && /^\/files\//.test(m.file)) {
        var a = document.createElement("a");
        a.href = m.file; a.target = "_blank"; a.rel = "noopener";
        a.textContent = "📎 " + (chat.getAttribute("data-attachment") || "");
        div.appendChild(document.createElement("br")); div.appendChild(a);
      }
      var meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = (m.author ? m.author + " · " : "") + new Date(m.at).toLocaleString();
      if (m.mine) {
        var tick = document.createElement("span");
        tick.className = "tick"; tick.textContent = "✓"; tick.title = chat.getAttribute("data-sent") || "";
        meta.appendChild(document.createTextNode(" · ")); meta.appendChild(tick);
      }
      div.appendChild(meta);
      chat.appendChild(div);
      last = m.id;
    };
    var apply = function (data) {
      (data.messages || []).forEach(render);
      (data.read || []).forEach(function (id) {
        var t = document.querySelector("#m-" + id + " .tick");
        if (t && !t.classList.contains("read")) {
          t.classList.add("read"); t.textContent = "✓✓"; t.title = chat.getAttribute("data-read") || "";
        }
      });
      if (data.messages && data.messages.length) chat.scrollTop = chat.scrollHeight;
    };
    var poll = function () {
      fetch(url + (last ? "?after=" + encodeURIComponent(last) : ""), { credentials: "same-origin",
        headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : { messages: [] }; })
        .then(apply).catch(function () { /* offline */ });
    };
    var startPolling = function () { if (!timer) timer = setInterval(poll, 5000); };
    var connect = function () {
      if (!window.WebSocket) { startPolling(); return; }
      var proto = location.protocol === "https:" ? "wss://" : "ws://";
      try {
        socket = new WebSocket(proto + location.host + chat.getAttribute("data-chat-ws") +
                               (last ? "?after=" + encodeURIComponent(last) : ""));
      } catch (e) { startPolling(); return; }
      socket.onopen = function () { if (timer) { clearInterval(timer); timer = null; } };
      socket.onmessage = function (ev) { try { apply(JSON.parse(ev.data)); } catch (e) { /* ignore */ } };
      socket.onclose = function () { socket = null; startPolling(); setTimeout(connect, 30000); };
    };
    chat.scrollTop = chat.scrollHeight;
    connect();
    var form = document.querySelector("[data-chat-form]");
    if (form) {
      form.addEventListener("submit", function (e) {
        var file = form.querySelector("input[type=file]");
        if (file && file.files && file.files.length) return;  // attachments go the classic way
        var body = form.querySelector("textarea");
        if (!body || !body.value.trim()) { e.preventDefault(); return; }
        e.preventDefault();
        var fd = new FormData(form);
        fetch(form.action, { method: "POST", body: fd, credentials: "same-origin",
                             headers: { "Accept": "application/json" } })
          .then(function (r) { if (!r.ok) throw new Error("send"); body.value = ""; if (!socket) poll(); })
          .catch(function () { form.submit(); });
      });
    }
  }

  // ---- Web Push subscription (FR-MOB-02) ----------------------------------------------
  var pushBox = document.getElementById("push");
  if (pushBox) {
    var status = pushBox.querySelector("[data-push-status]");
    var say = function (t) { if (status) status.textContent = t; };
    var csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
    var keyBytes = function (b64) {
      var pad = "=".repeat((4 - b64.length % 4) % 4), raw = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
      var out = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
      return out;
    };
    var send = function (url, body) {
      return fetch(url, { method: "POST", credentials: "same-origin", body: JSON.stringify(body),
        headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrfToken } });
    };
    var supported = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
    pushBox.querySelector("[data-push-enable]").addEventListener("click", function () {
      if (!supported) { say(pushBox.getAttribute("data-push-unsupported")); return; }
      Notification.requestPermission().then(function (perm) {
        if (perm !== "granted") { say(pushBox.getAttribute("data-push-denied")); return null; }
        return navigator.serviceWorker.ready.then(function (reg) {
          return reg.pushManager.subscribe({ userVisibleOnly: true,
            applicationServerKey: keyBytes(pushBox.getAttribute("data-push-key")) });
        }).then(function (sub) { return send("/account/push/subscribe", sub.toJSON()); })
          .then(function (r) { if (r && r.ok) { say(pushBox.getAttribute("data-push-on")); } });
      }).catch(function (e) { say(String(e && e.message || e)); });
    });
    pushBox.querySelector("[data-push-disable]").addEventListener("click", function () {
      if (!supported) { send("/account/push/unsubscribe", {}); return; }
      navigator.serviceWorker.ready.then(function (reg) { return reg.pushManager.getSubscription(); })
        .then(function (sub) {
          var ep = sub ? sub.endpoint : "";
          return (sub ? sub.unsubscribe() : Promise.resolve()).then(function () {
            return send("/account/push/unsubscribe", { endpoint: ep });
          });
        }).then(function () { say(pushBox.getAttribute("data-push-off")); });
    });
  }

  // ---- form helpers of the abdex.kz site: phone mask, checks while typing, password eye, no double submit
  //      (the server validates everything again; these only help the user see a mistake early)
  var me = document.currentScript || document.querySelector('script[src*="/static/js/app.js"]');
  var msg = function (k, d) { return (me && me.getAttribute("data-" + k)) || d; };
  var digits = function (v) { return (v || "").replace(/\D/g, ""); };

  function formatPhone(raw) {  // +7 (7XX) XXX-XX-XX
    var d = digits(raw);
    if (!d) return "";
    if (d[0] === "8") d = "7" + d.slice(1);
    if (d[0] !== "7") d = "7" + d;
    d = d.slice(0, 11);
    var out = "+7";
    if (d.length > 1) out += " (" + d.slice(1, 4);
    if (d.length >= 4) out += ")";
    if (d.length > 4) out += " " + d.slice(4, 7);
    if (d.length > 7) out += "-" + d.slice(7, 9);
    if (d.length > 9) out += "-" + d.slice(9, 11);
    return out;
  }

  function binOk(v) {  // the official control digit of BIN / IIN
    if (!/^\d{12}$/.test(v)) return false;
    var n = v.split("").map(Number), w1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], w2 = [3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2];
    var s = 0, i;
    for (i = 0; i < 11; i++) s += n[i] * w1[i];
    s %= 11;
    if (s === 10) { s = 0; for (i = 0; i < 11; i++) s += n[i] * w2[i]; s %= 11; if (s === 10) return false; }
    return s === n[11];
  }

  function problem(input) {
    var v = (input.value || "").trim();
    if (!v) return "";
    if (input.type === "tel") return digits(v).length === 11 ? "" : msg("err-phone", "Phone: +7 and 10 digits");
    if (input.type === "email") return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) ? "" : msg("err-email", "Check the e-mail");
    if (input.name === "bin_iin" || input.hasAttribute("data-bin")) return binOk(v) ? "" : msg("err-bin", "Check the BIN / IIN");
    return "";
  }

  function show(input, text) {
    var field = input.closest(".field");
    if (!field) return;
    var node = field.querySelector(".err[data-live]");
    if (!text) { if (node) node.remove(); if (!field.querySelector(".err:not([data-live])")) field.classList.remove("has-error"); return; }
    if (!node) { node = document.createElement("span"); node.className = "err"; node.setAttribute("data-live", ""); field.appendChild(node); }
    node.textContent = text;
    field.classList.add("has-error");
  }

  document.querySelectorAll('input[type="tel"]').forEach(function (input) {
    if (input.value) input.value = formatPhone(input.value);
    input.addEventListener("input", function () {
      var end = input.selectionStart === input.value.length;
      input.value = formatPhone(input.value);
      if (end) input.setSelectionRange(input.value.length, input.value.length);
    });
  });
  document.querySelectorAll('input[type="tel"], input[type="email"], input[name="bin_iin"], input[data-bin]').forEach(function (input) {
    if (input.name === "bin_iin") input.addEventListener("input", function () { input.value = digits(input.value).slice(0, 12); });
    // a message appearing on blur would shift the form under the pointer (the next click lands elsewhere):
    // messages appear on a submit attempt, then follow the field while it is being corrected
    var live = function () { if (input.closest(".field") && input.closest(".field").querySelector(".err[data-live]")) show(input, problem(input)); };
    input.addEventListener("blur", live);
    input.addEventListener("input", function () { if (!problem(input)) show(input, ""); });
  });

  document.querySelectorAll('input[type="password"]').forEach(function (input) {
    var wrap = document.createElement("span");
    wrap.className = "pw-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    var eye = document.createElement("button");
    eye.type = "button"; eye.className = "pw-eye"; eye.textContent = "👁";
    eye.setAttribute("aria-label", msg("show-password", "Show password"));
    eye.addEventListener("click", function () {
      var shown = input.type === "text";
      input.type = shown ? "password" : "text";
      eye.setAttribute("aria-label", msg(shown ? "show-password" : "hide-password", shown ? "Show password" : "Hide password"));
      eye.setAttribute("aria-pressed", shown ? "false" : "true");
    });
    wrap.appendChild(eye);
  });

  // a second tap on a slow connection must not send the form twice (the server also refuses duplicates)
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (e.defaultPrevented || form.hasAttribute("data-no-guard")) return;  // AJAX forms (chat) handle themselves
    var bad = null;
    form.querySelectorAll('input[type="tel"], input[type="email"], input[name="bin_iin"], input[data-bin]').forEach(function (input) {
      var p = problem(input); show(input, p); if (p && !bad) bad = input;
    });
    if (bad) { e.preventDefault(); bad.focus(); return; }
    var buttons = form.querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"]');
    setTimeout(function () { buttons.forEach(function (b) { b.disabled = true; }); }, 0);  // after the value is sent
    setTimeout(function () { buttons.forEach(function (b) { b.disabled = false; }); }, 8000);  // downloads stay on the page
  });

  // ---- tables -> stacked cards on phones: copy column headers into data-label -------
  document.querySelectorAll(".table-wrap table").forEach(function (t) {
    var heads = Array.prototype.map.call(t.querySelectorAll("thead th"), function (th) { return th.textContent.trim(); });
    if (!heads.length) return;
    t.querySelectorAll("tbody tr").forEach(function (tr) {
      Array.prototype.forEach.call(tr.children, function (td, i) {
        if (!td.hasAttribute("data-label") && heads[i] && !td.hasAttribute("colspan")) td.setAttribute("data-label", heads[i]);
      });
    });
  });

  // ---- mobile "more" sheet: close on outside tap / Escape -----------------------------
  var more = document.querySelector(".tab-more");
  if (more) {
    document.addEventListener("click", function (e) { if (more.open && !more.contains(e.target)) more.open = false; });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") more.open = false; });
  }

  // ---- PWA ----------------------------------------------------------------------------
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(function () { /* optional */ });
  }
})();
