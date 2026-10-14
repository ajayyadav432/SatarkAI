// SatarkAI Link Guard - background worker.
// Asks the SatarkAI app running on this computer about links, pages and e-mails.
// Everything is sent only to 127.0.0.1 (this computer), never to the internet.
const APP = "http://127.0.0.1:8000";
const TIMEOUT_MS = 1500;
const BATCH_TIMEOUT_MS = 8000;
const cache = new Map();          // url -> result of /api/check-urls (kept while the browser runs)
const MAX_CACHE = 5000;

function call(path, options, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout || TIMEOUT_MS);
  return fetch(APP + path, { ...options, signal: controller.signal })
    .then((res) => (res.ok ? res.json() : Promise.reject(new Error("status " + res.status))))
    .finally(() => clearTimeout(timer));
}

const post = (path, body, timeout) =>
  call(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }, timeout);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return false;

  // One link the user clicked.
  if (message.type === "check" && typeof message.url === "string") {
    call("/api/check-url?u=" + encodeURIComponent(message.url))
      .then((data) => sendResponse({
        ok: true, needs_warning: !!data.needs_warning, level: data.level, score: data.score,
        reason: data.factors && data.factors[0] ? data.factors[0].title : null,
        warning_page: APP + "/go?u=" + encodeURIComponent(message.url),
      }))
      // App not running or too slow: do not block the user's browsing.
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  // Many links on a page (to mark the risky ones).
  if (message.type === "checkMany" && Array.isArray(message.urls)) {
    const urls = message.urls.filter((u) => typeof u === "string").slice(0, 200);
    const todo = urls.filter((u) => !cache.has(u));
    const done = () => sendResponse({ ok: true, results: Object.fromEntries(urls.filter((u) => cache.has(u)).map((u) => [u, cache.get(u)])) });
    if (!todo.length) { done(); return false; }
    post("/api/check-urls", { urls: todo }, BATCH_TIMEOUT_MS)
      .then((data) => {
        for (const [u, r] of Object.entries(data.results || {})) cache.set(u, r);
        while (cache.size > MAX_CACHE) cache.delete(cache.keys().next().value);
        done();
      })
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  // A page reports how many risky links it found: shown as a number on the toolbar icon.
  if (message.type === "stats" && sender.tab) {
    const n = Number(message.risky) || 0;
    const off = message.enabled === false;
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: off ? "OFF" : (n > 0 ? String(n) : "") });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: off ? "#6b7280" : "#dc3545" });
    return false;
  }

  // An e-mail opened in Gmail.
  if (message.type === "ingestEmail" && typeof message.text === "string") {
    post("/api/ingest", {
      text: message.text.slice(0, 20000), channel: "email", source: "gmail-web",
      sender: message.sender ? String(message.sender).slice(0, 320) : null,
      ref: message.ref ? String(message.ref).slice(0, 300) : null,
    }, BATCH_TIMEOUT_MS)
      .then((data) => sendResponse({ ok: true, result: data, case_page: APP + "/#case/" + data.case_id }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }
  return false;
});

// Toolbar icon shows "OFF" while protection is switched off in the popup.
function showOnOff(enabled) {
  chrome.action.setBadgeText({ text: enabled ? "" : "OFF" });
  chrome.action.setBadgeBackgroundColor({ color: enabled ? "#dc3545" : "#6b7280" });
  chrome.action.setTitle({ title: "SatarkAI Link Guard: protection " + (enabled ? "on" : "off") });
}
chrome.storage.local.get({ enabled: true }, (v) => showOnOff(v.enabled !== false));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.enabled) showOnOff(changes.enabled.newValue !== false);
});
