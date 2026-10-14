// Popup of SatarkAI Link Guard: protection switch, app status, and what was found on the current page.
// Text from pages is only ever inserted with textContent.
(function () {
  "use strict";
  const APP = "http://127.0.0.1:8000";
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  const pill = (level, score) => el("span", "pill lvl-" + level, level + (score !== undefined ? " " + score : ""));

  $("version").textContent = "Version " + chrome.runtime.getManifest().version;

  // For testing the popup in a normal tab: popup.html?tab=<id> inspects that tab.
  const forcedTab = Number(new URLSearchParams(location.search).get("tab")) || null;
  function currentTab(cb) {
    if (forcedTab) { cb({ id: forcedTab }); return; }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => cb(tabs && tabs[0]));
  }

  function showSwitch(on) {
    $("enabled").checked = on;
    document.body.classList.toggle("off", !on);
    $("state-text").textContent = on ? "Protection on" : "Protection off";
    $("state-sub").textContent = on ? "Pages, links and Gmail are checked" : "Nothing is checked or blocked";
    $("rescan").disabled = !on;
  }

  function showApp() {
    const box = $("app-status");
    fetch(APP + "/api/health", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(() => { box.className = "status ok"; $("app-text").textContent = "Connected to SatarkAI on this computer"; })
      .catch(() => { box.className = "status bad"; $("app-text").textContent = "SatarkAI app is not running. Start it with ./run.sh"; });
  }

  function showPage() {
    const body = $("page-body"), list = $("risky");
    list.replaceChildren();
    currentTab((tab) => {
      if (!tab) { body.textContent = "No page open."; return; }
      chrome.tabs.sendMessage(tab.id, { type: "getStats" }, (s) => {
        if (chrome.runtime.lastError || !s) {
          body.textContent = "This page cannot be checked (browser pages and the Chrome Web Store are off-limits to extensions). Reload the page if it just opened.";
          return;
        }
        body.replaceChildren();
        if (!s.enabled) { body.textContent = "Protection is off."; return; }
        if (s.satarkApp) { body.textContent = "This is the SatarkAI app itself."; return; }
        const line = el("div");
        if (s.page) line.append(pill(s.page.level, s.page.score), el("span", "", s.page.level === "Safe" || s.page.level === "Low" ? "Website address looks fine" : "Risky website"));
        else line.append(el("span", "muted", s.local ? "Page on this computer (address not checked)" : "Website address not checked yet"));
        body.append(line);
        const n = s.risky.length;
        body.append(el("div", n ? "" : "muted", n ? "⚠ " + n + " risky link" + (n === 1 ? "" : "s") + " marked on this page:" :
          "No risky links found" + (s.checked ? " (" + s.checked + " checked)." : ".")));
        for (const r of s.risky) {
          const li = el("li");
          li.append(pill(r.level, r.score), document.createTextNode(r.url));
          if (r.reason) li.append(el("small", "", r.reason));
          list.append(li);
        }
      });
    });
  }

  chrome.storage.local.get({ enabled: true }, (v) => { showSwitch(v.enabled !== false); showApp(); showPage(); });

  $("enabled").addEventListener("change", (e) => {
    const on = e.target.checked;
    chrome.storage.local.set({ enabled: on }, () => { showSwitch(on); setTimeout(showPage, 400); });
  });

  $("rescan").addEventListener("click", () => {
    $("page-body").textContent = "Scanning…";
    currentTab((tab) => {
      if (!tab) return;
      chrome.tabs.sendMessage(tab.id, { type: "rescan" }, () => { void chrome.runtime.lastError; setTimeout(showPage, 300); });
    });
  });

  $("open-app").addEventListener("click", () => { chrome.tabs.create({ url: APP + "/" }); window.close(); });
})();
