// Applies the saved theme before first paint (loaded in <head>, no inline scripts under the CSP).
(function () {
  try {
    var t = localStorage.getItem("itam-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable: follow the system setting */ }
})();
