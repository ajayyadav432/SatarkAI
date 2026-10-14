// SatarkAI Link Guard - runs on every page.
// When you click a link to another site, the link is checked first.
// Risky link  -> the SatarkAI warning page opens instead.
// Other links -> open as usual. If the SatarkAI app is not running, nothing is blocked.
(function () {
  "use strict";
  const LOCAL = new Set(["127.0.0.1", "localhost", "[::1]"]);

  function open(url, newTab) {
    if (newTab) window.open(url, "_blank", "noopener");
    else window.location.assign(url);
  }

  document.addEventListener("click", function (event) {
    if (event.defaultPrevented || event.button !== 0) return;
    const link = event.target && event.target.closest ? event.target.closest("a[href]") : null;
    if (!link) return;
    let url;
    try { url = new URL(link.href, window.location.href); } catch (e) { return; }
    if (url.protocol !== "http:" && url.protocol !== "https:") return;
    if (url.hostname === window.location.hostname) return;      // links inside the same site are not checked
    if (LOCAL.has(url.hostname)) return;                         // the SatarkAI app itself

    const newTab = link.target === "_blank" || event.ctrlKey || event.metaKey || event.shiftKey;
    event.preventDefault();
    event.stopImmediatePropagation();
    let done = false;
    const proceed = () => { if (!done) { done = true; open(url.href, newTab); } };
    const fallback = setTimeout(proceed, 2000);                  // never leave a click hanging

    try {
      chrome.runtime.sendMessage({ type: "check", url: url.href }, function (answer) {
        clearTimeout(fallback);
        if (done) return;
        if (chrome.runtime.lastError || !answer || !answer.ok || !answer.needs_warning) { proceed(); return; }
        done = true;
        open(answer.warning_page, newTab);
      });
    } catch (e) {
      clearTimeout(fallback);
      proceed();
    }
  }, true);
})();
