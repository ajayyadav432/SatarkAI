// SatarkAI Link Guard - runs on every page.
// 1. When a page loads, its address is checked. A risky page gets a warning bar at the top.
// 2. Links to other sites on the page are checked; risky ones get a small red badge.
// 3. When you click a link to another site, it is checked first; risky links open the warning page.
// If the SatarkAI app is not running, nothing is blocked and nothing is shown.
(function () {
  "use strict";
  const LOCAL = new Set(["127.0.0.1", "localhost", "[::1]"]);
  const COLORS = { Medium: "#f5a524", High: "#f07a4a", Critical: "#dc3545" };
  const send = (msg) => new Promise((resolve) => {
    try { chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? null : r)); }
    catch (e) { resolve(null); }
  });
  /** Set several style properties (CSSOM, so page security policies do not block it). */
  const css = (el, props) => { for (const [k, v] of Object.entries(props)) el.style.setProperty(k, v, "important"); return el; };
  const isSatarkApp = LOCAL.has(location.hostname) && location.port === "8000";   // the SatarkAI app itself

  // ---------- 3. click guard ----------
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
    send({ type: "check", url: url.href }).then((answer) => {
      clearTimeout(fallback);
      if (done) return;
      if (!answer || !answer.ok || !answer.needs_warning) { proceed(); return; }
      done = true;
      open(answer.warning_page, newTab);
    });
  }, true);

  if (isSatarkApp || window.top !== window) return;   // no bar or badges on the SatarkAI app or inside frames

  // ---------- 1. warning bar for a risky page ----------
  function pageBar(r) {
    if (document.getElementById("satark-page-bar")) return;
    const bar = css(document.createElement("div"), {
      position: "fixed", top: "0", left: "0", right: "0", "z-index": "2147483647", display: "flex", "align-items": "center",
      gap: "12px", padding: "10px 16px", background: COLORS[r.level] || COLORS.Critical, color: "#fff",
      font: "600 14px/1.4 system-ui, sans-serif", "box-shadow": "0 4px 16px rgba(0,0,0,.25)",
    });
    bar.id = "satark-page-bar";
    bar.setAttribute("role", "alert");
    const text = document.createElement("span");
    css(text, { flex: "1" });
    text.textContent = "⚠ SatarkAI: this website looks dangerous (" + r.level + ", " + r.score + "/100)" +
      (r.reason ? " — " + r.reason : "") + ". Do not enter passwords, OTPs or card details.";
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "Dismiss";
    css(close, { background: "rgba(255,255,255,.2)", color: "#fff", border: "1px solid rgba(255,255,255,.5)", "border-radius": "6px",
      padding: "4px 10px", cursor: "pointer", font: "600 13px system-ui, sans-serif" });
    close.addEventListener("click", () => bar.remove());
    bar.append(text, close);
    (document.body || document.documentElement).append(bar);
  }

  // ---------- 2. badges on risky links ----------
  const checked = new WeakSet();

  function badge(link, r) {
    if (link.nextSibling && link.nextSibling.dataset && link.nextSibling.dataset.satarkBadge !== undefined) return;
    const b = document.createElement("span");
    b.dataset.satarkBadge = "";
    b.textContent = "⚠ " + r.level;
    b.title = "SatarkAI: " + r.level + " risk (" + r.score + "/100)" + (r.reason ? ". " + r.reason : "");
    css(b, { display: "inline-block", "margin-left": "4px", padding: "0 6px", "border-radius": "999px", background: COLORS[r.level] || COLORS.Critical,
      color: "#fff", font: "700 11px/18px system-ui, sans-serif", "vertical-align": "middle", "white-space": "nowrap", cursor: "help" });
    link.after(b);
    css(link, { outline: "2px solid " + (COLORS[r.level] || COLORS.Critical), "outline-offset": "1px", "border-radius": "2px" });
  }

  async function scanLinks() {
    const links = [];
    for (const a of document.querySelectorAll("a[href]")) {
      if (checked.has(a)) continue;
      checked.add(a);
      let u;
      try { u = new URL(a.href, location.href); } catch (e) { continue; }
      if ((u.protocol !== "http:" && u.protocol !== "https:") || u.hostname === location.hostname || LOCAL.has(u.hostname)) continue;
      links.push([a, u.href]);
      if (links.length >= 200) break;
    }
    if (!links.length) return;
    const answer = await send({ type: "checkMany", urls: [...new Set(links.map((l) => l[1]))] });
    if (!answer || !answer.ok) return;
    for (const [a, href] of links) {
      const r = answer.results[href];
      if (r && r.needs_warning) badge(a, r);
    }
  }

  let timer = null;
  const scheduleScan = () => { clearTimeout(timer); timer = setTimeout(scanLinks, 600); };

  function start() {
    if ((location.protocol === "http:" || location.protocol === "https:") && !LOCAL.has(location.hostname)) {   // pages on this computer are not checked
      send({ type: "check", url: location.href }).then((r) => { if (r && r.ok && r.needs_warning) pageBar(r); });
    }
    scanLinks();
    new MutationObserver(scheduleScan).observe(document.documentElement, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
