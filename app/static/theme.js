// Applied before the page paints, so there is no flash of the wrong theme.
(function () {
  try {
    var saved = localStorage.getItem("satark-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch (e) { /* storage blocked: follow the system setting */ }
})();
