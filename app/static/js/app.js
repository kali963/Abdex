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

  // ---- deal chat: polling (FR-CHAT-06 degradation path) -------------------------------
  var chat = document.querySelector("[data-chat]");
  if (chat) {
    var url = chat.getAttribute("data-chat");
    var last = chat.getAttribute("data-last") || "";
    var poll = function () {
      fetch(url + (last ? "?after=" + encodeURIComponent(last) : ""), { credentials: "same-origin",
        headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : { messages: [] }; })
        .then(function (data) {
          data.messages.forEach(function (m) {
            if (document.getElementById("m-" + m.id)) return;
            var div = document.createElement("div");
            div.id = "m-" + m.id;
            div.className = "msg " + (m.kind === "system" ? "system" : (m.mine ? "mine" : ""));
            div.textContent = m.text;
            var meta = document.createElement("span");
            meta.className = "meta";
            meta.textContent = (m.author ? m.author + " · " : "") + new Date(m.at).toLocaleString();
            div.appendChild(meta);
            chat.appendChild(div);
            last = m.id;
          });
          if (data.messages.length) chat.scrollTop = chat.scrollHeight;
        }).catch(function () { /* offline */ });
    };
    chat.scrollTop = chat.scrollHeight;
    setInterval(poll, 5000);
  }

  // ---- 3D tilt for panels (pointer devices only, respects reduced motion) ----------
  var fine = window.matchMedia && window.matchMedia("(hover: hover) and (pointer: fine)").matches;
  var calm = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (fine && !calm) {
    document.querySelectorAll(".panel-3d, .stat").forEach(function (el) {
      var raf = 0;
      el.addEventListener("pointermove", function (e) {
        var r = el.getBoundingClientRect();
        var x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(function () {
          var max = r.width > 520 ? 2.5 : 6;  // big panels tilt less
          el.style.setProperty("--ry", ((x - 0.5) * max * 2).toFixed(2) + "deg");
          el.style.setProperty("--rx", ((0.5 - y) * max * 2).toFixed(2) + "deg");
          el.style.setProperty("--mx", (x * 100).toFixed(1) + "%");
          el.style.setProperty("--my", (y * 100).toFixed(1) + "%");
          el.classList.add("is-tilting");
        });
      });
      el.addEventListener("pointerleave", function () {
        cancelAnimationFrame(raf);
        el.style.setProperty("--rx", "0deg"); el.style.setProperty("--ry", "0deg");
        el.classList.remove("is-tilting");
      });
    });
  }

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
