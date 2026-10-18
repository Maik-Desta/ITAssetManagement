// ITAM UI helpers. No inline scripts: everything is wired through data attributes (CSP: script-src 'self').
(function () {
  "use strict";

  // Mobile navigation
  document.querySelectorAll("[data-menu-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelector(".sidebar").classList.toggle("open");
    });
  });

  // Auto-refresh (NOC console)
  var refresh = parseInt(document.body.dataset.refresh || "0", 10);
  if (refresh > 0) {
    setTimeout(function () {
      if (!document.querySelector("form :focus")) window.location.reload();
    }, refresh * 1000);
  }

  // Confirmation prompts
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // Auto-submit controls (checklists, filters)
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () { el.form.submit(); });
  });

  // Chart tooltips: any element with data-tip
  var tip = document.createElement("div");
  tip.id = "tooltip";
  tip.hidden = true;
  document.body.appendChild(tip);
  function showTip(e) {
    var t = e.currentTarget.getAttribute("data-tip");
    if (!t) return;
    tip.textContent = t;
    tip.hidden = false;
    var x = e.clientX, y = e.clientY;
    if (x === undefined || (x === 0 && y === 0)) {
      var r = e.currentTarget.getBoundingClientRect();
      x = r.left + r.width / 2; y = r.top;
    }
    tip.style.left = Math.min(x + 12, window.innerWidth - tip.offsetWidth - 8) + "px";
    tip.style.top = Math.max(y - tip.offsetHeight - 10, 4) + "px";
  }
  function hideTip() { tip.hidden = true; }
  document.querySelectorAll("[data-tip]").forEach(function (el) {
    el.addEventListener("mousemove", showTip);
    el.addEventListener("focus", showTip);
    el.addEventListener("mouseleave", hideTip);
    el.addEventListener("blur", hideTip);
  });

  // Dependent selects: <select data-filter-by="#branch" > options carry data-parent
  document.querySelectorAll("select[data-filter-by]").forEach(function (sel) {
    var parent = document.querySelector(sel.dataset.filterBy);
    if (!parent) return;
    function apply() {
      var v = parent.value;
      Array.prototype.forEach.call(sel.options, function (o) {
        if (!o.dataset.parent) return;
        var show = !v || o.dataset.parent === v;
        o.hidden = !show;
        o.disabled = !show;
        if (!show && o.selected) sel.value = "";
      });
    }
    parent.addEventListener("change", apply);
    apply();
  });

  // Show/hide blocks depending on a select value: data-show-when="#field=VAL1,VAL2"
  document.querySelectorAll("[data-show-when]").forEach(function (block) {
    var spec = block.dataset.showWhen.split("=");
    var ctl = document.querySelector(spec[0]);
    var values = spec[1].split(",");
    if (!ctl) return;
    function apply() { block.classList.toggle("hidden", values.indexOf(ctl.value) === -1); }
    ctl.addEventListener("change", apply);
    apply();
  });

  // Camera QR scanning (mobile audit / change execution). Falls back to keyboard-wedge scanners.
  document.querySelectorAll("[data-camera-scan]").forEach(function (btn) {
    var input = document.querySelector(btn.dataset.cameraScan);
    if (!("BarcodeDetector" in window) || !navigator.mediaDevices) {
      btn.hidden = true;
      return;
    }
    btn.addEventListener("click", async function () {
      var box = document.querySelector(btn.dataset.videoBox);
      var video = document.createElement("video");
      video.setAttribute("playsinline", "");
      box.innerHTML = "";
      box.appendChild(video);
      var stream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      } catch (err) {
        box.textContent = "Camera unavailable: " + err.message;
        return;
      }
      video.srcObject = stream;
      await video.play();
      var detector = new window.BarcodeDetector({ formats: ["qr_code", "code_128"] });
      var stop = function () { stream.getTracks().forEach(function (t) { t.stop(); }); box.innerHTML = ""; };
      (async function loop() {
        try {
          var codes = await detector.detect(video);
          if (codes.length) {
            input.value = codes[0].rawValue;
            stop();
            if (input.form && btn.dataset.autoSubmit) input.form.submit();
            return;
          }
        } catch (e) { /* keep trying */ }
        requestAnimationFrame(loop);
      })();
    });
  });

  // Keep scan input focused for handheld scanners
  var scan = document.querySelector("[data-autofocus]");
  if (scan) scan.focus();
})();

document.querySelectorAll("[data-print]").forEach(function (b) {
  b.addEventListener("click", function () { window.print(); });
});

// ---------------------------------------------------------------------------------------------
// Dashboard design layer: theme switch, sortable / filterable tables, KPI count-up.
// ---------------------------------------------------------------------------------------------
(function () {
  "use strict";
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Theme: Auto (system) → Light → Dark, remembered per browser.
  var root = document.documentElement;
  var LABELS = { auto: "Auto", light: "Light", dark: "Dark" };
  function currentTheme() { return root.getAttribute("data-theme") || "auto"; }
  function paintToggle(btn) {
    var t = currentTheme();
    btn.dataset.mode = t;
    var label = btn.querySelector(".theme-label");
    if (label) label.textContent = LABELS[t];
    btn.setAttribute("aria-label", "Colour theme: " + LABELS[t].toLowerCase() + ". Click to change.");
  }
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    paintToggle(btn);
    btn.addEventListener("click", function () {
      var next = { auto: "light", light: "dark", dark: "auto" }[currentTheme()];
      if (next === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", next);
      try { if (next === "auto") localStorage.removeItem("itam-theme"); else localStorage.setItem("itam-theme", next); }
      catch (e) { /* not persisted */ }
      paintToggle(btn);
    });
  });

  // Tables ------------------------------------------------------------------------------------
  function cellValue(cell) {
    if (!cell) return "";
    if (cell.dataset.sort !== undefined) return cell.dataset.sort;
    return (cell.textContent || "").replace(/\s+/g, " ").trim();
  }
  function asNumber(text) {
    // "1,234", "98.5%", "22 / 250", "-3": the leading number. Dates and codes stay text.
    if (/^\d{4}-\d{2}-\d{2}/.test(text)) return null;
    var m = text.replace(/,/g, "").match(/^-?\d+(\.\d+)?(?=\s|%|$|\s*\/)/);
    return m ? parseFloat(m[0]) : null;
  }
  function plainRows(tbody) {
    var rows = Array.prototype.slice.call(tbody.rows);
    var simple = rows.every(function (r) {
      return !Array.prototype.some.call(r.cells, function (c) { return c.colSpan > 1; });
    });
    return simple ? rows : null;
  }

  document.querySelectorAll("table").forEach(function (table, index) {
    if (table.closest(".table-view") || table.classList.contains("no-enhance")) return;
    var thead = table.tHead, tbody = table.tBodies[0];
    if (!thead || !tbody || thead.rows.length !== 1) return;
    table.classList.add("enhanced");
    // One line per row, except cells holding real prose (descriptions, summaries).
    Array.prototype.forEach.call(tbody.querySelectorAll("td"), function (td) {
      if ((td.textContent || "").trim().length > 70 || td.querySelector("form, textarea, ul")) td.classList.add("long");
    });
    var rows = plainRows(tbody);
    if (!rows || rows.length < 2) return;

    // Click-to-sort headers (buttons, so they work from the keyboard too).
    Array.prototype.forEach.call(thead.rows[0].cells, function (th, col) {
      var text = th.textContent.trim();
      if (!text) return;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "th-sort";
      btn.appendChild(document.createTextNode(text));
      var arrow = document.createElement("span");
      arrow.className = "sort-arrow";
      arrow.setAttribute("aria-hidden", "true");
      btn.appendChild(arrow);
      th.textContent = "";
      th.appendChild(btn);
      th.setAttribute("aria-sort", "none");
      btn.addEventListener("click", function () {
        var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
        Array.prototype.forEach.call(thead.rows[0].cells, function (o) { o.setAttribute("aria-sort", "none"); });
        th.setAttribute("aria-sort", dir);
        var current = Array.prototype.slice.call(tbody.rows);
        var numeric = current.every(function (r) {
          var v = cellValue(r.cells[col]);
          return v === "" || v === "—" || asNumber(v) !== null;
        });
        current.sort(function (a, b) {
          var x = cellValue(a.cells[col]), y = cellValue(b.cells[col]);
          var r;
          if (numeric) {
            var nx = asNumber(x), ny = asNumber(y);
            nx = nx === null ? -Infinity : nx; ny = ny === null ? -Infinity : ny;
            r = nx - ny;
          } else {
            r = x.localeCompare(y, undefined, { numeric: true, sensitivity: "base" });
          }
          return dir === "ascending" ? r : -r;
        });
        current.forEach(function (r) { tbody.appendChild(r); });
      });
    });

    // Long tables: a scroll box sized to the screen (sticky header) and an instant filter.
    var wrap = table.parentElement;
    if (!wrap.classList.contains("table-wrap")) {
      wrap = document.createElement("div");
      wrap.className = "table-wrap";
      table.parentNode.insertBefore(wrap, table);
      wrap.appendChild(table);
    }
    if (rows.length >= 12) {
      wrap.classList.add("table-scroll");
      var bar = document.createElement("div");
      bar.className = "table-tools";
      var id = "tf-" + index;
      var label = document.createElement("label");
      label.className = "sr-only";
      label.htmlFor = id;
      label.textContent = "Filter table rows";
      var input = document.createElement("input");
      input.type = "search";
      input.id = id;
      input.placeholder = "Filter " + rows.length + " rows…";
      var count = document.createElement("span");
      count.className = "table-count";
      count.textContent = rows.length + " rows";
      bar.appendChild(label);
      bar.appendChild(input);
      bar.appendChild(count);
      wrap.parentNode.insertBefore(bar, wrap);
      input.addEventListener("input", function () {
        var q = input.value.trim().toLowerCase(), shown = 0;
        Array.prototype.forEach.call(tbody.rows, function (r) {
          var hit = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
          r.hidden = !hit;
          if (hit) shown++;
        });
        count.textContent = q ? shown + " of " + rows.length + " rows" : rows.length + " rows";
      });
    }
  });

  // KPI count-up: whole numbers animate from zero once, on load.
  if (!reduceMotion) {
    document.querySelectorAll(".kpi-value, .tile .value").forEach(function (el) {
      var node = el.firstChild;
      if (!node || node.nodeType !== 3) return;
      var m = node.nodeValue.match(/^(\s*)(\d{1,3}(?:,\d{3})*|\d+)(\s*)$/);
      if (!m) return;
      var target = parseInt(m[2].replace(/,/g, ""), 10);
      if (!target || target < 2) return;
      var start = null, dur = 700;
      function step(ts) {
        if (start === null) start = ts;
        var p = Math.min(1, (ts - start) / dur), eased = 1 - Math.pow(1 - p, 3);
        node.nodeValue = m[1] + Math.round(target * eased).toLocaleString("en-US") + m[3];
        if (p < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }
})();

// Executive dashboard views: one screen each, switched in place. Without JS every view shows.
(function () {
  "use strict";
  var bar = document.querySelector("[data-board-tabs]");
  if (!bar) return;
  var views = Array.prototype.slice.call(document.querySelectorAll(".board-view"));
  var buttons = Array.prototype.slice.call(bar.querySelectorAll("button[data-view]"));
  document.body.classList.add("has-board-views");
  function show(name, focusTarget) {
    if (!views.some(function (v) { return v.dataset.view === name; })) name = "overview";
    views.forEach(function (v) { v.hidden = v.dataset.view !== name; });
    buttons.forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.view === name)); });
    try { sessionStorage.setItem("itam-board-view", name); } catch (e) { /* not remembered */ }
    if (focusTarget) focusTarget.scrollIntoView({ block: "start" });
  }
  function fromHash() {
    var id = decodeURIComponent((location.hash || "").slice(1));
    var target = id && document.getElementById(id);
    var view = target && target.closest(".board-view");
    if (view) { show(view.dataset.view, target); return true; }
    return false;
  }
  buttons.forEach(function (b) { b.addEventListener("click", function () { show(b.dataset.view); }); });
  window.addEventListener("hashchange", fromHash);
  if (!fromHash()) {
    var saved = null;
    try { saved = sessionStorage.getItem("itam-board-view"); } catch (e) { /* default view */ }
    show(saved || "overview");
  }
})();
