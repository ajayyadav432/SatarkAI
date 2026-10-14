// SatarkAI Link Guard - background worker.
// Asks the SatarkAI app running on this computer whether a link is risky.
// Links are sent only to 127.0.0.1 (this computer), never to the internet.
const APP = "http://127.0.0.1:8000";
const TIMEOUT_MS = 1500;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "check" || typeof message.url !== "string") return false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  fetch(APP + "/api/check-url?u=" + encodeURIComponent(message.url), { signal: controller.signal })
    .then((res) => (res.ok ? res.json() : Promise.reject(new Error("status " + res.status))))
    .then((data) => sendResponse({
      ok: true, needs_warning: !!data.needs_warning, level: data.level, score: data.score,
      warning_page: APP + "/go?u=" + encodeURIComponent(message.url),
    }))
    // App not running or too slow: do not block the user's browsing.
    .catch((err) => sendResponse({ ok: false, error: String(err) }))
    .finally(() => clearTimeout(timer));
  return true; // the answer is sent asynchronously
});
