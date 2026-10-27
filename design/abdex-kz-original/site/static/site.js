/* AbdEX site.js — base UX for forms (vanilla JS)
   - phone formatting (+7...)
   - validation (required, email, IIN/BIN)
   - inline errors
   - disable submit / show loading ("Отправка...")
   - city suggest (origin/destination) via /api/suggest/cities
   - safe: works even if some fields don't exist
*/

(() => {
  "use strict";

  // ---------- helpers ----------
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const isEmpty = (v) => (v ?? "").toString().trim().length === 0;

  const debounce = (fn, ms = 150) => {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  };

  function digitsOnly(v) {
    return (v || "").toString().replace(/\D/g, "");
  }

  // ---------- UI: error rendering ----------
  function fieldKey(field) {
    return field.id || field.name || "field";
  }

  function ensureErrorNode(field) {
    const key = fieldKey(field);

    let node = field.parentElement?.querySelector(
      `.field-error[data-for="${CSS.escape(key)}"]`
    );
    if (!node) {
      node = document.createElement("div");
      node.className = "field-error";
      node.dataset.for = key;
      node.style.marginTop = "6px";
      node.style.display = "none";
      field.insertAdjacentElement("afterend", node);
    }
    return node;
  }

  function showError(field, message) {
    const node = ensureErrorNode(field);
    node.textContent = message;
    node.style.display = "block";

    field.classList.remove("is-valid");
    field.classList.add("is-invalid");
  }

  function clearError(field) {
    const key = fieldKey(field);

    const node =
      field.parentElement?.querySelector(
        `.field-error[data-for="${CSS.escape(key)}"]`
      ) ||
      (field.nextElementSibling &&
      field.nextElementSibling.classList?.contains("field-error")
        ? field.nextElementSibling
        : null);

    if (node) {
      node.style.display = "none";
      node.textContent = "";
    }

    field.classList.remove("is-invalid");
  }

  function setSuccess(field) {
    const key = fieldKey(field);

    const node =
      field.parentElement?.querySelector(
        `.field-error[data-for="${CSS.escape(key)}"]`
      ) ||
      (field.nextElementSibling &&
      field.nextElementSibling.classList?.contains("field-error")
        ? field.nextElementSibling
        : null);

    if (node) {
      node.style.display = "none";
      node.textContent = "";
    }

    field.classList.remove("is-invalid");
    field.classList.add("is-valid");
  }

  // ---------- formatters ----------
  // Phone formatter: prefers +7 (KZ/RU). Keeps only digits, formats as +7 707 123 45 67
  function formatKZPhone(raw) {
    let digits = (raw || "").toString().replace(/\D/g, "");

    // 8XXXXXXXXXX -> 7XXXXXXXXXX
    if (digits.length === 11 && digits.startsWith("8")) digits = "7" + digits.slice(1);

    // If 10 digits -> assume leading 7
    // If 10 digits -> assume missing country code ONLY if it's not already starting with "77"
    if (digits.length === 10 && !digits.startsWith("77")) {
      digits = "7" + digits;
    }

    // limit to 11 digits max (E.164 for +7)
    if (digits.length > 11) digits = digits.slice(0, 11);

    if (digits.length === 0) return "";

    const c = digits.slice(0, 1);   // 7
    const a = digits.slice(1, 4);   // 707
    const b = digits.slice(4, 7);   // 123
    const d = digits.slice(7, 9);   // 45
    const e = digits.slice(9, 11);  // 67

    let out = `+${c}`;
    if (a) out += ` ${a}`;
    if (b) out += ` ${b}`;
    if (d) out += ` ${d}`;
    if (e) out += ` ${e}`;
    return out.trim();
  }

  // ---------- validators ----------
  function isValidEmail(v) {
    const s = (v || "").toString().trim();
    if (s.length === 0) return true;
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
  }

  function isValidIIN(v) {
    const d = digitsOnly(v);
    if (d.length === 0) return true;
    return d.length === 12;
  }

  function isValidBIN(v) {
    const d = digitsOnly(v);
    if (d.length === 0) return true;
    return d.length === 12;
  }

  function isValidPhone(v) {
    let d = digitsOnly(v);
    if (d.length === 0) return true;

    if (d.length === 11 && d.startsWith("8")) d = "7" + d.slice(1);
    if (d.length === 10) d = "7" + d;

    return d.length === 11 && d.startsWith("7");
  }

  // required attribute OR data-required="1/true" OR label contains "*"
  function isRequired(field) {
    if (field.hasAttribute("required")) return true;
    if (field.dataset.required === "1" || field.dataset.required === "true") return true;

    const id = field.id;
    if (id) {
      const lab = document.querySelector(`label[for="${CSS.escape(id)}"]`);
      if (lab && lab.textContent.includes("*")) return true;
    }
    return false;
  }

  function validateField(field) {
    clearError(field);

    const val = field.value;

    // required
    if (isRequired(field) && isEmpty(val)) {
      showError(field, "Заполните поле");
      return false;
    }

    // email
    if (field.type === "email" || field.name?.toLowerCase().includes("email")) {
      if (!isValidEmail(val)) {
        showError(field, "Введите корректный email");
        return false;
      }
    }

    // phone
    if (
      field.type === "tel" ||
      field.name?.toLowerCase().includes("phone") ||
      field.name?.toLowerCase().includes("тел")
    ) {
      if (!isValidPhone(val)) {
        showError(field, "Введите корректный номер телефона");
        return false;
      }
    }

    // iin
    if (field.name?.toLowerCase().includes("iin") || field.name?.toLowerCase().includes("иин")) {
      if (!isValidIIN(val)) {
        showError(field, "ИИН должен быть 12 цифр");
        return false;
      }
    }

    // bin
    if (field.name?.toLowerCase().includes("bin") || field.name?.toLowerCase().includes("бин")) {
      if (!isValidBIN(val)) {
        showError(field, "БИН должен быть 12 цифр");
        return false;
      }
    }

    // numeric min/max if present
    if (field.type === "number") {
      const n = Number(val);
      if (!isEmpty(val) && Number.isFinite(n)) {
        const min = field.getAttribute("min");
        const max = field.getAttribute("max");
        if (min !== null && n < Number(min)) {
          showError(field, `Минимум: ${min}`);
          return false;
        }
        if (max !== null && n > Number(max)) {
          showError(field, `Максимум: ${max}`);
          return false;
        }
      }
    }

    if (!isEmpty(val) || isRequired(field)) setSuccess(field);
    return true;
  }

  function getFormFields(form) {
    return $$("input, select, textarea", form).filter((f) => {
      if (f.disabled) return false;
      const t = (f.type || "").toLowerCase();
      if (t === "hidden" || t === "submit" || t === "button" || t === "reset") return false;
      return true;
    });
  }

  // ---------- behavior ----------
  function attachPhoneMask(form) {
    const phoneFields = $$('input[type="tel"], input[name*="phone"], input[name*="Phone"]', form);

    phoneFields.forEach((field) => {
      field.addEventListener("input", () => {
        field.value = formatKZPhone(field.value);
      });

      field.addEventListener("blur", () => {
        field.value = formatKZPhone(field.value);
        validateField(field);
      });
    });
  }

  function attachLiveValidation(form) {
    const fields = getFormFields(form);

    const onInput = debounce((e) => {
      const field = e.target;

      if (!isRequired(field) && isEmpty(field.value)) {
        clearError(field);
        field.classList.remove("is-valid");
        return;
      }

      validateField(field);
    }, 200);

    fields.forEach((field) => {
      field.addEventListener("input", onInput);
      field.addEventListener("change", () => validateField(field));
      field.addEventListener("blur", () => validateField(field));
    });
  }

  function attachSubmitGuard(form) {
    form.addEventListener("submit", (e) => {
      const fields = getFormFields(form);

      let ok = true;
      for (const f of fields) {
        const v = validateField(f);
        if (!v) ok = false;
      }

      if (!ok) {
        e.preventDefault();
        const firstBad = fields.find((f) => f.classList.contains("is-invalid"));
        if (firstBad) firstBad.focus();
        return;
      }

      // Disable submit button and show loading
      const btn = form.querySelector('button[type="submit"], input[type="submit"]');
      if (btn) {
        btn.dataset._oldText = btn.tagName === "BUTTON" ? btn.textContent : btn.value;

        // ✅ нужный текст
        if (btn.tagName === "BUTTON") btn.textContent = "Отправка...";
        else btn.value = "Отправка...";

        btn.disabled = true;
        btn.style.opacity = "0.85";
        btn.style.cursor = "not-allowed";
      }
    });

    // If user navigates back (bfcache), re-enable button
    window.addEventListener("pageshow", () => {
      const btn = form.querySelector('button[type="submit"], input[type="submit"]');
      if (btn && btn.disabled) {
        btn.disabled = false;
        btn.style.opacity = "";
        btn.style.cursor = "";
        const old = btn.dataset._oldText;
        if (old) {
          if (btn.tagName === "BUTTON") btn.textContent = old;
          else btn.value = old;
        }
      }
    });
  }

  function initForms() {
    const forms = $$("form");
    forms.forEach((form) => {
      attachPhoneMask(form);
      attachLiveValidation(form);
      attachSubmitGuard(form);
    });
  }

  // ---------- city suggest (origin/destination) ----------
 function initCitySuggest() {
  const inputs = $$("input.js-city-suggest");
  if (!inputs.length) return;

  const localCache = new Map(); // q -> items

  function highlight(text, q) {
    const s = (text || "").toString();
    const qq = (q || "").toString().trim();
    if (!qq) return s.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const esc = qq.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(esc, "ig");
    return s
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(re, (m) => `<b>${m}</b>`);
  }

  function createDropdown(input) {
    const wrap = document.createElement("div");
    wrap.className = "city-dd";
    wrap.style.position = "relative";

    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const list = document.createElement("div");
    list.className = "city-dd-list";
    list.style.display = "none";
    wrap.appendChild(list);

    const state = { open: false, items: [], idx: -1 };

    const hide = () => {
      state.open = false;
      state.items = [];
      state.idx = -1;
      list.style.display = "none";
      list.innerHTML = "";
    };

    const show = () => {
      state.open = true;
      list.style.display = "block";
    };

    const setActive = (newIdx) => {
      state.idx = newIdx;
      list.querySelectorAll(".city-dd-item").forEach((el, i) => {
        el.classList.toggle("is-active", i === state.idx);
      });
    };

    document.addEventListener("click", (e) => {
      if (!wrap.contains(e.target)) hide();
    });

    return { list, state, hide, show, setActive };
  }

  async function fetchCities(q) {
    const key = q.toLowerCase();
    if (localCache.has(key)) return localCache.get(key);

    try {
      const res = await fetch(`/api/suggest/cities?q=${encodeURIComponent(q)}`);
      if (!res.ok) return [];
      const data = await res.json();
      const items = data?.items || [];
      localCache.set(key, items);
      return items;
    } catch {
      return [];
    }
  }

  inputs.forEach((input) => {
    const dd = createDropdown(input);

    const render = (items, q) => {
      dd.state.items = items;
      dd.state.idx = -1;

      dd.list.innerHTML = items.map((x) => {
        const value = (x.value || "").replace(/"/g, "&quot;");
        const label = (x.label || "").replace(/"/g, "&quot;");
        const lat = x.lat ?? "";
        const lon = x.lon ?? "";
        const labelHtml = highlight(x.label || "", q);

        return `
          <div class="city-dd-item"
               data-value="${value}"
               data-label="${label}"
               data-lat="${lat}"
               data-lon="${lon}">
            ${labelHtml}
          </div>`;
      }).join("");

      dd.list.querySelectorAll(".city-dd-item").forEach((el, i) => {
        // pointerdown — чтобы не терялся фокус
        el.addEventListener("pointerdown", (e) => {
          e.preventDefault();

          const v = el.getAttribute("data-value") || "";
          const lab = el.getAttribute("data-label") || "";
          const lat = el.getAttribute("data-lat") || "";
          const lon = el.getAttribute("data-lon") || "";

          input.value = v;

          // определяем origin / destination по name
          const n = (input.getAttribute("name") || "").toLowerCase();
          const prefix = n.includes("dest") ? "destination" : "origin";

          const form = input.closest("form") || document;

          const setHidden = (name, val) => {
            const h = form.querySelector(`input[type="hidden"][name="${name}"]`);
            if (h) h.value = val;
          };

          setHidden(`${prefix}_label`, lab);
          setHidden(`${prefix}_lat`, lat);
          setHidden(`${prefix}_lon`, lon);

          dd.hide();
          input.dispatchEvent(new Event("change"));
        });

        el.addEventListener("mouseenter", () => dd.setActive(i));
      });

      if (items.length) dd.show();
      else dd.hide();
    };

    const run = debounce(async () => {
      const q = (input.value || "").trim();
      if (q.length < 2) {
        dd.hide();
        return;
      }
      const items = await fetchCities(q);
      render(items, q);
    }, 350);

    input.addEventListener("input", run);
    input.addEventListener("focus", run);

    input.addEventListener("keydown", (e) => {
      if (!dd.state.open) return;

      if (e.key === "Escape") {
        dd.hide();
        return;
      }

      if (e.key === "ArrowDown") {
        e.preventDefault();
        dd.setActive(Math.min(dd.state.idx + 1, dd.state.items.length - 1));
      }

      if (e.key === "ArrowUp") {
        e.preventDefault();
        dd.setActive(Math.max(dd.state.idx - 1, 0));
      }

      if (e.key === "Enter") {
        if (dd.state.idx >= 0 && dd.state.items[dd.state.idx]) {
          e.preventDefault();
          const it = dd.state.items[dd.state.idx];
          input.value = it.value || "";

          const n = (input.getAttribute("name") || "").toLowerCase();
          const prefix = n.includes("dest") ? "destination" : "origin";
          const form = input.closest("form") || document;

          const setHidden = (name, val) => {
            const h = form.querySelector(`input[type="hidden"][name="${name}"]`);
            if (h) h.value = val ?? "";
          };

          setHidden(`${prefix}_label`, it.label);
          setHidden(`${prefix}_lat`, it.lat);
          setHidden(`${prefix}_lon`, it.lon);

          dd.hide();
          input.dispatchEvent(new Event("change"));
        }
      }
    });
  });
}
  function initAbdCalendars() {
    const roots = $$(".js-abd-cal");
    if (!roots.length) return;

    const monthNames = [
      "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
      "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
    ];

    const pad = (n) => String(n).padStart(2, "0");

    function toYmd(d) {
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    }

    function fromYmd(v) {
      const s = (v || "").toString().trim();
      if (!s) return null;
      const m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (!m) return null;
      return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
    }

    function toRu(d) {
      return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
    }

    function sameDay(a, b) {
      return !!a && !!b && toYmd(a) === toYmd(b);
    }

    function inRange(d, from, to) {
      if (!from || !to) return false;
      const x = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
      const a = new Date(from.getFullYear(), from.getMonth(), from.getDate()).getTime();
      const b = new Date(to.getFullYear(), to.getMonth(), to.getDate()).getTime();
      return x >= a && x <= b;
    }

    let opened = null;

    function closeAll(except = null) {
      roots.forEach((root) => {
        if (root === except) return;
        const popup = root.querySelector(".js-abd-cal-popup");
        if (popup) popup.hidden = true;
        root.classList.remove("is-open");
      });
      if (!except) opened = null;
    }

    roots.forEach((root) => {
      const mode = (root.dataset.mode || "single").trim();

      const trigger = root.querySelector(".js-abd-cal-trigger");
      const label = root.querySelector(".js-abd-cal-label");
      const popup = root.querySelector(".js-abd-cal-popup");
      const monthNode = root.querySelector(".js-abd-cal-month");
      const grid = root.querySelector(".js-abd-cal-grid");
      const prevBtn = root.querySelector(".js-abd-cal-prev");
      const nextBtn = root.querySelector(".js-abd-cal-next");
      const clearBtn = root.querySelector(".js-abd-cal-clear");
      const applyBtn = root.querySelector(".js-abd-cal-apply");

      const singleInput = root.querySelector(".js-abd-cal-value");
      const anchorInput = root.querySelector(".js-abd-cal-anchor");
      const fromInput = root.querySelector(".js-abd-cal-from");
      const toInput = root.querySelector(".js-abd-cal-to");

      let start = null;
      let end = null;

      if (mode === "range") {
        start = fromYmd(fromInput?.value || anchorInput?.value || "");
        end = fromYmd(toInput?.value || "");
      } else {
        start = fromYmd(singleInput?.value || "");
      }

      let viewBase = start || new Date();
      let view = new Date(viewBase.getFullYear(), viewBase.getMonth(), 1);

      function syncLabel() {
        if (!label) return;

        if (mode === "range") {
          if (start && end) {
            label.textContent = `${toRu(start)} — ${toRu(end)}`;
          } else if (start) {
            label.textContent = `${toRu(start)} — ...`;
          } else {
            label.textContent = "Выберите период";
          }
        } else {
          label.textContent = start ? toRu(start) : "Выберите дату";
        }
      }

      function syncInputs() {
        if (mode === "range") {
          if (fromInput) fromInput.value = start ? toYmd(start) : "";
          if (toInput) toInput.value = end ? toYmd(end) : "";
          if (anchorInput) anchorInput.value = start ? toYmd(start) : "";
        } else {
          if (singleInput) singleInput.value = start ? toYmd(start) : "";
        }
        syncLabel();
      }

      function render() {
        if (!monthNode || !grid) return;

        monthNode.textContent = `${monthNames[view.getMonth()]} ${view.getFullYear()}`;
        grid.innerHTML = "";

        const firstDay = new Date(view.getFullYear(), view.getMonth(), 1);
        const daysInMonth = new Date(view.getFullYear(), view.getMonth() + 1, 0).getDate();
        const startOffset = (firstDay.getDay() + 6) % 7;

        for (let i = 0; i < startOffset; i++) {
          const empty = document.createElement("div");
          empty.className = "abd-cal-day is-empty";
          grid.appendChild(empty);
        }

        for (let day = 1; day <= daysInMonth; day++) {
          const d = new Date(view.getFullYear(), view.getMonth(), day);

          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "abd-cal-day";
          btn.textContent = String(day);

          if (mode === "range") {
            if (start && end && inRange(d, start, end)) btn.classList.add("is-in-range");
            if (sameDay(d, start)) btn.classList.add("is-start");
            if (sameDay(d, end)) btn.classList.add("is-end");
            if (sameDay(d, start) && sameDay(d, end)) btn.classList.add("is-single");
          } else {
            if (sameDay(d, start)) btn.classList.add("is-single");
          }

          btn.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();

            const picked = new Date(d.getFullYear(), d.getMonth(), d.getDate());

            if (mode === "range") {
              if (!start || (start && end)) {
                start = picked;
                end = null;
              } else if (picked.getTime() < start.getTime()) {
                end = start;
                start = picked;
              } else {
                end = picked;
              }

              syncInputs();
              render();

              // range-календарь не закрываем после выбора дат
              popup.hidden = false;
              root.classList.add("is-open");
              opened = root;
            } else {
              start = picked;
              syncInputs();
              render();
              popup.hidden = true;
              root.classList.remove("is-open");
              opened = null;
            }
          });

          grid.appendChild(btn);
        }
      }

      function open() {
        closeAll(root);
        popup.hidden = false;
        root.classList.add("is-open");
        opened = root;
        render();
      }

      function close() {
        popup.hidden = true;
        root.classList.remove("is-open");
        if (opened === root) opened = null;
      }

      trigger?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        if (popup.hidden) open();
        else close();
      });

      popup?.addEventListener("click", (e) => {
        e.stopPropagation();
      });

      prevBtn?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        view = new Date(view.getFullYear(), view.getMonth() - 1, 1);
        render();
      });

      nextBtn?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        view = new Date(view.getFullYear(), view.getMonth() + 1, 1);
        render();
      });

      clearBtn?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        start = null;
        end = null;
        syncInputs();
        render();
      });

      applyBtn?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        if (mode === "range" && start && !end) {
          end = start;
          syncInputs();
        }
        close();
      });

      document.addEventListener("click", (e) => {
        if (!root.contains(e.target)) close();
      });

      syncInputs();
      render();
    });
  }


  // ---------- login modal ----------
  function initPlanBuilder() {
    const roots = $$(".js-plan-builder");
    if (!roots.length) return;

    const pad = (n) => String(n).padStart(2, "0");
    const toYmd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const toRu = (d) => `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
    const fromYmd = (value) => {
      const v = (value || "").trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
      const [y, m, d] = v.split("-").map(Number);
      return new Date(y, m - 1, d);
    };

    const monthWeekdayDate = (year, monthIndex, weekdayIso, position) => {
      const target = weekdayIso % 7;
      const days = [];
      const lastDay = new Date(year, monthIndex + 1, 0).getDate();
      for (let day = 1; day <= lastDay; day++) {
        const dt = new Date(year, monthIndex, day);
        const jsWeekday = dt.getDay();
        const isoWeekday = jsWeekday === 0 ? 7 : jsWeekday;
        if (isoWeekday === weekdayIso) days.push(dt);
      }
      if (!days.length) return null;
      if (position === -1) return days[days.length - 1];
      return days[position - 1] || null;
    };

    roots.forEach((root) => {
      const form = root.closest("form");
      if (!form) return;

      const typeInput = root.querySelector(".js-plan-schedule-type");
      const typeButtons = $$(".js-plan-mode-btn", root);
      const panels = $$(".js-plan-panel[data-panel]", root);

      const weekdaysInput = root.querySelector(".js-plan-weekdays-input");
      const weekdayButtons = $$(".js-plan-weekday", root);

      const monthlyModeInput = root.querySelector(".js-plan-monthly-mode");
      const monthlyModeButtons = $$(".js-plan-monthly-mode-btn", root);
      const monthlyPanels = $$(".js-plan-monthly-panel", root);
      const monthDaysInput = root.querySelector(".js-plan-month-days-input");
      const monthDayButtons = $$(".js-plan-month-day", root);

      const customDatesInput = root.querySelector(".js-plan-custom-dates-input");
      const customPicker = root.querySelector(".js-plan-custom-date-picker");
      const customAddBtn = root.querySelector(".js-plan-custom-date-add");
      const customList = root.querySelector(".js-plan-custom-dates-list");

      const previewList = root.querySelector(".js-plan-preview-list");
      const previewMeta = root.querySelector(".js-plan-preview-meta");

      const periodFromInput = form.querySelector('input[name="load_date_from"]');
      const periodToInput = form.querySelector('input[name="load_date_to"]');
      const trucksInput = form.querySelector('input[name="trucks_per_occurrence"]');
      const leadDaysInput = form.querySelector('select[name="lead_days"]');
      const monthPositionInput = form.querySelector('select[name="schedule_month_position"]');
      const monthWeekdayInput = form.querySelector('select[name="schedule_month_weekday"]');
      const intervalWeeksInput = form.querySelector('select[name="schedule_interval_weeks"]');

      let scheduleType = (typeInput?.value || root.dataset.initScheduleType || "weekly").trim() || "weekly";
      let monthlyMode = (monthlyModeInput?.value || "dates").trim() || "dates";
      let weekdays = new Set((weekdaysInput?.value || root.dataset.initWeekdays || "").split(",").map((x) => x.trim()).filter(Boolean));
      let monthDays = new Set((monthDaysInput?.value || root.dataset.initMonthDays || "").split(",").map((x) => x.trim()).filter(Boolean));
      let customDates = (customDatesInput?.value || root.dataset.initCustomDates || "").split(",").map((x) => x.trim()).filter(Boolean);

      const sortCustomDates = () => {
        customDates = customDates.filter(Boolean).sort();
      };

      const syncHiddenInputs = () => {
        if (typeInput) typeInput.value = scheduleType;
        if (weekdaysInput) weekdaysInput.value = Array.from(weekdays).sort((a, b) => Number(a) - Number(b)).join(",");
        if (monthDaysInput) monthDaysInput.value = Array.from(monthDays).sort((a, b) => Number(a) - Number(b)).join(",");
        if (customDatesInput) customDatesInput.value = customDates.join(",");
        if (monthlyModeInput) monthlyModeInput.value = monthlyMode;
      };

      const renderButtons = () => {
        typeButtons.forEach((btn) => btn.classList.toggle("is-active", btn.dataset.value === scheduleType));
        panels.forEach((panel) => { panel.hidden = panel.dataset.panel !== scheduleType; });
        weekdayButtons.forEach((btn) => btn.classList.toggle("is-active", weekdays.has(btn.dataset.value)));
        monthDayButtons.forEach((btn) => btn.classList.toggle("is-active", monthDays.has(btn.dataset.value)));
        monthlyModeButtons.forEach((btn) => btn.classList.toggle("is-active", btn.dataset.value === monthlyMode));
        monthlyPanels.forEach((panel) => { panel.hidden = panel.dataset.monthlyPanel !== monthlyMode; });
      };

      const renderCustomDates = () => {
        if (!customList) return;
        sortCustomDates();
        customList.innerHTML = "";
        if (!customDates.length) {
          const empty = document.createElement("div");
          empty.className = "plan-note";
          empty.textContent = "Добавь одну или несколько дат.";
          customList.appendChild(empty);
          return;
        }
        customDates.forEach((item) => {
          const dt = fromYmd(item);
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "plan-chip is-active";
          chip.textContent = dt ? toRu(dt) : item;
          chip.title = "Удалить дату";
          chip.addEventListener("click", () => {
            customDates = customDates.filter((x) => x !== item);
            syncHiddenInputs();
            renderCustomDates();
            updatePreview();
          });
          customList.appendChild(chip);
        });
      };

      const buildPreviewDates = () => {
        const from = fromYmd(periodFromInput?.value || "");
        const to = fromYmd(periodToInput?.value || "");
        if (!from || !to || to < from) return [];

        const dates = [];

        if (scheduleType === "weekly") {
          const interval = Math.max(1, Number(intervalWeeksInput?.value || 1));
          const weekdayNums = Array.from(weekdays).map(Number).filter((n) => n >= 1 && n <= 7);
          if (!weekdayNums.length) return [];
          const baseMonday = new Date(from);
          baseMonday.setDate(from.getDate() - ((from.getDay() + 6) % 7));
          for (let cur = new Date(from); cur <= to; cur.setDate(cur.getDate() + 1)) {
            const isoWeekday = cur.getDay() === 0 ? 7 : cur.getDay();
            const weekIndex = Math.floor((cur - baseMonday) / 86400000 / 7);
            if (weekIndex % interval === 0 && weekdayNums.includes(isoWeekday)) {
              dates.push(new Date(cur));
            }
          }
        } else if (scheduleType === "monthly") {
          if (monthlyMode === "weekday") {
            const pos = Number(monthPositionInput?.value || 1);
            const wd = Number(monthWeekdayInput?.value || 1);
            let y = from.getFullYear();
            let m = from.getMonth();
            while (y < to.getFullYear() || (y === to.getFullYear() && m <= to.getMonth())) {
              const dt = monthWeekdayDate(y, m, wd, pos);
              if (dt && dt >= from && dt <= to) dates.push(dt);
              m += 1;
              if (m > 11) { m = 0; y += 1; }
            }
          } else {
            const pickedDays = Array.from(monthDays).map(Number).filter((n) => n >= 1 && n <= 31);
            if (!pickedDays.length) return [];
            let y = from.getFullYear();
            let m = from.getMonth();
            while (y < to.getFullYear() || (y === to.getFullYear() && m <= to.getMonth())) {
              const lastDay = new Date(y, m + 1, 0).getDate();
              pickedDays.forEach((day) => {
                if (day > lastDay) return;
                const dt = new Date(y, m, day);
                if (dt >= from && dt <= to) dates.push(dt);
              });
              m += 1;
              if (m > 11) { m = 0; y += 1; }
            }
          }
        } else if (scheduleType === "custom_dates") {
          customDates.forEach((item) => {
            const dt = fromYmd(item);
            if (dt && dt >= from && dt <= to) dates.push(dt);
          });
        }

        const uniq = [];
        const seen = new Set();
        dates.sort((a, b) => a - b).forEach((dt) => {
          const key = toYmd(dt);
          if (seen.has(key)) return;
          seen.add(key);
          uniq.push(dt);
        });
        return uniq;
      };

      const updatePreview = () => {
        if (!previewList || !previewMeta) return;
        syncHiddenInputs();
        renderButtons();
        renderCustomDates();

        const dates = buildPreviewDates();
        const trucks = Math.max(1, Number(trucksInput?.value || 1));
        const leadDays = Math.max(1, Number(leadDaysInput?.value || 6));

        if (!dates.length) {
          previewMeta.textContent = "Пока пусто";
          previewList.textContent = "По текущим условиям внутри периода не найдено дат.";
          return;
        }

        const firstGenerateDate = new Date(dates[0]);
        firstGenerateDate.setDate(firstGenerateDate.getDate() - leadDays);
        previewMeta.textContent = `${dates.length} дат • ${dates.length * trucks} машин`;

        const lines = dates.slice(0, 8).map((dt) => `• ${toRu(dt)} — ${trucks} маш.`);
        if (dates.length > 8) lines.push(`• и ещё ${dates.length - 8} дат`);
        lines.push(`Первая автогенерация заявки: ${toRu(firstGenerateDate)}`);
        previewList.innerHTML = lines.map((line) => `<div>${line}</div>`).join("");
      };

      typeButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
          scheduleType = btn.dataset.value || "weekly";
          updatePreview();
        });
      });

      weekdayButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
          const value = btn.dataset.value;
          if (!value) return;
          if (weekdays.has(value)) weekdays.delete(value);
          else weekdays.add(value);
          updatePreview();
        });
      });

      monthDayButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
          const value = btn.dataset.value;
          if (!value) return;
          if (monthDays.has(value)) monthDays.delete(value);
          else monthDays.add(value);
          updatePreview();
        });
      });

      monthlyModeButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
          monthlyMode = btn.dataset.value || "dates";
          updatePreview();
        });
      });

      customAddBtn?.addEventListener("click", () => {
        const value = (customPicker?.value || "").trim();
        if (!value) return;
        if (!customDates.includes(value)) customDates.push(value);
        if (customPicker) customPicker.value = "";
        updatePreview();
      });

      [periodFromInput, periodToInput, trucksInput, leadDaysInput, monthPositionInput, monthWeekdayInput, intervalWeeksInput].forEach((node) => {
        node?.addEventListener("change", updatePreview);
        node?.addEventListener("input", updatePreview);
      });

      syncHiddenInputs();
      renderButtons();
      renderCustomDates();
      updatePreview();
    });
  }

  function initLoginModal() {
    const modal = document.getElementById("loginModal");
    const openBtn = document.getElementById("openLogin");
    const closeBtn = document.getElementById("closeLogin");

    const form = document.getElementById("loginForm");
    const login = document.getElementById("loginField");
    const pass = document.getElementById("passwordField");

    const err = document.getElementById("loginError");
    const forgot = document.getElementById("forgotBtn");

    if (!modal || !openBtn || !closeBtn || !form) return;

    function openModal() {
      modal.classList.add("open");
      modal.setAttribute("aria-hidden", "false");
      err?.classList.add("hidden");
      forgot?.classList.add("hidden");
      setTimeout(() => login?.focus(), 10);
    }

    function closeModal() {
      modal.classList.remove("open");
      modal.setAttribute("aria-hidden", "true");
    }

    openBtn.addEventListener("click", openModal);
    closeBtn.addEventListener("click", closeModal);

    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal();
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });

    // Empty fields => show forgot
    form.addEventListener("submit", (e) => {
      const l = (login?.value || "").trim();
      const p = (pass?.value || "").trim();

      if (!l || !p) {
        e.preventDefault();
        if (err) {
          err.textContent = "Введите логин и пароль";
          err.classList.remove("hidden");
        }
        forgot?.classList.remove("hidden");
        return;
      }
    });

    forgot?.addEventListener("click", () => {
      if (!err) return;
      err.textContent = "Если не помните данные — напишите администратору для восстановления доступа.";
      err.classList.remove("hidden");
    });
  }

    function initPlanRangePicker() {
    const roots = $$(".js-plan-range");
    if (!roots.length) return;

    const monthNames = [
      "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
      "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
    ];

    const pad = (n) => String(n).padStart(2, "0");

    function toYmd(d) {
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    }

    function fromYmd(s) {
      const v = (s || "").trim();
      if (!v) return null;
      const m = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (!m) return null;
      return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
    }

    function toRu(d) {
      return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`;
    }

    function sameDay(a, b) {
      return !!a && !!b && toYmd(a) === toYmd(b);
    }

    function inRange(d, a, b) {
      if (!a || !b) return false;
      const x = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
      const s = new Date(a.getFullYear(), a.getMonth(), a.getDate()).getTime();
      const e = new Date(b.getFullYear(), b.getMonth(), b.getDate()).getTime();
      return x >= s && x <= e;
    }

    roots.forEach((root) => {
      const field = root.closest(".req-field");
      const fromInput = field.querySelector(".js-plan-range-from");
      const toInput = field.querySelector(".js-plan-range-to");
      const loadDateInput = field.querySelector('input[name="load_date"]');

      const trigger = root.querySelector(".js-plan-range-trigger");
      const label = root.querySelector(".js-plan-range-label");
      const popup = root.querySelector(".js-plan-range-popup");
      const monthNode = root.querySelector(".js-plan-range-month");
      const grid = root.querySelector(".js-plan-range-grid");
      const prevBtn = root.querySelector(".js-plan-range-prev");
      const nextBtn = root.querySelector(".js-plan-range-next");
      const clearBtn = root.querySelector(".js-plan-range-clear");
      const applyBtn = root.querySelector(".js-plan-range-apply");

      let start = fromYmd(fromInput?.value || "");
      let end = fromYmd(toInput?.value || "");
      let view = start ? new Date(start.getFullYear(), start.getMonth(), 1) : new Date(new Date().getFullYear(), new Date().getMonth(), 1);

      function syncLabel() {
        if (start && end) {
          label.textContent = `${toRu(start)} — ${toRu(end)}`;
        } else if (start) {
          label.textContent = `${toRu(start)} — ...`;
        } else {
          label.textContent = "Выберите период отгрузок";
        }
      }

      function syncInputs() {
        if (fromInput) fromInput.value = start ? toYmd(start) : "";
        if (toInput) toInput.value = end ? toYmd(end) : "";
        if (loadDateInput) loadDateInput.value = start ? toYmd(start) : "";
        syncLabel();
      }

      function render() {
        monthNode.textContent = `${monthNames[view.getMonth()]} ${view.getFullYear()}`;
        grid.innerHTML = "";

        const firstDay = new Date(view.getFullYear(), view.getMonth(), 1);
        const daysInMonth = new Date(view.getFullYear(), view.getMonth() + 1, 0).getDate();
        const startOffset = (firstDay.getDay() + 6) % 7;

        for (let i = 0; i < startOffset; i++) {
          const empty = document.createElement("div");
          empty.className = "plan-range-day is-empty";
          grid.appendChild(empty);
        }

        for (let day = 1; day <= daysInMonth; day++) {
          const d = new Date(view.getFullYear(), view.getMonth(), day);
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "plan-range-day";
          btn.textContent = String(day);

          if (start && end && inRange(d, start, end)) {
            btn.classList.add("is-in-range");
          }
          if (sameDay(d, start)) {
            btn.classList.add("is-start");
          }
          if (sameDay(d, end)) {
            btn.classList.add("is-end");
          }
          if (sameDay(d, start) && sameDay(d, end)) {
            btn.classList.add("is-single");
          }

          btn.addEventListener("click", () => {
            const picked = new Date(d.getFullYear(), d.getMonth(), d.getDate());

            if (!start || (start && end)) {
              start = picked;
              end = null;
            } else if (picked.getTime() < start.getTime()) {
              end = start;
              start = picked;
            } else {
              end = picked;
            }

            syncInputs();
            render();
          });

          grid.appendChild(btn);
        }
      }

      function open() {
        popup.hidden = false;
        root.classList.add("is-open");
        render();
      }

      function close() {
        popup.hidden = true;
        root.classList.remove("is-open");
      }

      trigger?.addEventListener("click", () => {
        if (popup.hidden) open();
        else close();
      });

      prevBtn?.addEventListener("click", () => {
        view = new Date(view.getFullYear(), view.getMonth() - 1, 1);
        render();
      });

      nextBtn?.addEventListener("click", () => {
        view = new Date(view.getFullYear(), view.getMonth() + 1, 1);
        render();
      });

      clearBtn?.addEventListener("click", () => {
        start = null;
        end = null;
        syncInputs();
        render();
      });

      applyBtn?.addEventListener("click", () => {
        if (start && !end) {
          end = start;
          syncInputs();
        }
        close();
      });

      document.addEventListener("click", (e) => {
        if (!root.contains(e.target)) {
          close();
        }
      });

      syncInputs();
      render();
    });
  }
  // ---------- boot ----------
  document.addEventListener("DOMContentLoaded", () => {
    initForms();
    initCitySuggest();
    initAbdCalendars();
    initPlanBuilder();
    initLoginModal();
  });

  async function refreshNotifBadge() {
    const badge = document.getElementById("notifBadge");
    if (!badge) return;

    try {
      const r = await fetch("/notifications/unread_count");
      const data = await r.json();
      const n = Number(data.count || 0);

      if (n > 0) {
        badge.textContent = String(n);
        badge.classList.remove("hidden");
      } else {
        badge.classList.add("hidden");
      }
    } catch (e) {
      // молча
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    refreshNotifBadge();
    setInterval(refreshNotifBadge, 15000);
  });
})();

