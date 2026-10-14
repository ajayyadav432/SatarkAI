// SatarkAI Link Guard - runs on every page.
// 1. When a page loads, its address is checked. A risky page gets a warning bar at the top.
// 2. Links to other sites on the page are checked; risky ones get a small red badge.
// 3. When you click a link to another site, it is checked first; risky links open the warning page.
// If the SatarkAI app is not running, nothing is blocked and nothing is shown.
// The switch in the extension popup turns all of this off and on (stored as "enabled").
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
  const topFrame = window.top === window;

  let enabled = true;
  // What was found on this page; the popup asks for it.
  const stats = { page: null, risky: [], checked: 0, appReachable: null };

  function report() {
    if (topFrame) send({ type: "stats", risky: enabled ? stats.risky.length : 0, enabled: enabled });
  }

  // ---------- 3. click guard ----------
  function open(url, newTab) {
    if (newTab) window.open(url, "_blank", "noopener");
    else window.location.assign(url);
  }

  document.addEventListener("click", function (event) {
    if (!enabled || event.defaultPrevented || event.button !== 0) return;
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
  let checked = new WeakSet();

  function badge(link, r) {
    if (link.nextSibling && link.nextSibling.dataset && link.nextSibling.dataset.satarkBadge !== undefined) return;
    const b = document.createElement("span");
    b.dataset.satarkBadge = "";
    b.textContent = "⚠ " + r.level;
    b.title = "SatarkAI: " + r.level + " risk (" + r.score + "/100)" + (r.reason ? ". " + r.reason : "");
    css(b, { display: "inline-block", "margin-left": "4px", padding: "0 6px", "border-radius": "999px", background: COLORS[r.level] || COLORS.Critical,
      color: "#fff", font: "700 11px/18px system-ui, sans-serif", "vertical-align": "middle", "white-space": "nowrap", cursor: "help" });
    link.after(b);
    link.dataset.satarkMarked = "";
    css(link, { outline: "2px solid " + (COLORS[r.level] || COLORS.Critical), "outline-offset": "1px", "border-radius": "2px" });
  }

  /** Remove every badge, outline and bar (when protection is switched off, or before a rescan). */
  function clearMarks() {
    document.querySelectorAll("[data-satark-badge]").forEach((b) => b.remove());
    document.querySelectorAll("[data-satark-marked]").forEach((a) => {
      a.style.removeProperty("outline"); a.style.removeProperty("outline-offset"); a.style.removeProperty("border-radius");
      delete a.dataset.satarkMarked;
    });
    const bar = document.getElementById("satark-page-bar");
    if (bar) bar.remove();
    checked = new WeakSet();
    stats.page = null; stats.risky = []; stats.checked = 0;
  }

  async function scanLinks() {
    if (!enabled) return;
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
    stats.appReachable = !!(answer && answer.ok);
    if (!answer || !answer.ok || !enabled) return;
    stats.checked += links.length;
    for (const [a, href] of links) {
      const r = answer.results[href];
      if (r && r.needs_warning) {
        badge(a, r);
        if (!stats.risky.some((x) => x.url === href)) stats.risky.push({ url: href, level: r.level, score: r.score, reason: r.reason });
      }
    }
    report();
  }

  function checkPage() {
    if (!enabled || !(location.protocol === "http:" || location.protocol === "https:") || LOCAL.has(location.hostname)) return;   // pages on this computer are not checked
    send({ type: "check", url: location.href }).then((r) => {
      stats.appReachable = !!(r && r.ok);
      if (!r || !r.ok || !enabled) return;
      stats.page = { level: r.level, score: r.score, reason: r.reason };
      if (r.needs_warning) pageBar(r);
      report();
    });
  }

  // The popup asks what was found, or asks for a rescan.
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!topFrame || !msg) return false;
    if (msg.type === "getStats") {
      sendResponse({ ...stats, enabled: enabled, url: location.href, local: LOCAL.has(location.hostname), satarkApp: isSatarkApp });
      return false;
    }
    if (msg.type === "rescan" && !isSatarkApp) {
      clearMarks();
      checkPage();
      scanLinks().then(() => sendResponse({ ok: true }));
      return true;
    }
    return false;
  });

  if (isSatarkApp || !topFrame) return;   // no bar or badges on the SatarkAI app or inside frames

  let timer = null;
  const scheduleScan = () => { clearTimeout(timer); timer = setTimeout(scanLinks, 600); };

  function start() {
    chrome.storage.local.get({ enabled: true }, (v) => {
      enabled = v.enabled !== false;
      report();
      if (!enabled) return;
      checkPage();
      scanLinks();
    });
    new MutationObserver(() => { if (enabled) scheduleScan(); }).observe(document.documentElement, { childList: true, subtree: true });
    // React at once when the popup switch is used.
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local" || !changes.enabled) return;
      enabled = changes.enabled.newValue !== false;
      if (enabled) { checkPage(); scanLinks(); } else { clearMarks(); }
      report();
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
})();
