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
