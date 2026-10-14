// SatarkAI Link Guard - Gmail in the browser.
// When an e-mail is opened, its subject, sender, text and link targets are sent to the SatarkAI app on
// this computer, and a verdict bar is shown above the e-mail.
// Gmail does not document its page structure. These class names have been used by Gmail for years:
//   div.a3s      message body          h2.hP     subject          span.gD[email]  sender
// If Gmail changes them, the bar simply does not appear; nothing else breaks.
(function () {
  "use strict";
  const COLORS = { Safe: "#16a34a", Low: "#6b7280", Medium: "#f5a524", High: "#f07a4a", Critical: "#dc3545" };
  let done = new WeakSet();
  let enabled = true;   // the switch in the extension popup
  const css = (el, props) => { for (const [k, v] of Object.entries(props)) el.style.setProperty(k, v, "important"); return el; };
  const send = (msg) => new Promise((resolve) => {
    try { chrome.runtime.sendMessage(msg, (r) => resolve(chrome.runtime.lastError ? null : r)); }
    catch (e) { resolve(null); }
  });

  function hash(s) {   // short stable id when Gmail gives none
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
    return "h" + (h >>> 0).toString(36);
  }

  function readMail(body) {
    const msg = body.closest("[data-message-id], [data-legacy-message-id], .adn") || body.parentElement;
    const subject = (document.querySelector("h2.hP") || {}).innerText || "";
    const from = msg && msg.querySelector("span.gD[email]");
    const text = (body.innerText || "").trim();
    const links = [...body.querySelectorAll("a[href]")].map((a) => a.href)
      .filter((u) => /^https?:/i.test(u) && !text.includes(u));
    const full = subject + "\n\n" + text + (links.length ? "\n\nLinks in this e-mail:\n" + [...new Set(links)].slice(0, 20).join("\n") : "");
    const ref = (msg && (msg.getAttribute("data-message-id") || msg.getAttribute("data-legacy-message-id"))) || hash(subject + text);
    return { text: full, sender: from ? from.getAttribute("email") : null, ref: ref };
  }

  function bar(body, info, caseUrl) {
    const r = info;
    const box = css(document.createElement("div"), {
      display: "flex", "align-items": "center", gap: "10px", margin: "0 0 12px", padding: "10px 14px",
      "border-radius": "10px", border: "1px solid " + (COLORS[r.level] || "#999"), "border-left": "6px solid " + (COLORS[r.level] || "#999"),
      background: "#fff", color: "#0b1f18", font: "14px/1.45 system-ui, sans-serif",
    });
    box.dataset.satarkBar = "";
    const pill = css(document.createElement("b"), { background: COLORS[r.level] || "#999", color: "#fff", padding: "2px 10px",
      "border-radius": "999px", "white-space": "nowrap", font: "700 13px system-ui, sans-serif" });
    pill.textContent = r.level + " " + r.score;
    const text = css(document.createElement("span"), { flex: "1" });
    const reasons = (r.reasons || []).slice(0, 2).join(" · ");
    text.textContent = "SatarkAI: " + (r.level === "Safe" || r.level === "Low" ? "no strong scam signs found." : r.summary || "risky e-mail.") +
      (reasons ? " " + reasons + "." : "") +
      (r.block ? " ⛔ This sender has sent " + r.block.count + " risky e-mails: block the sender." : "");
    box.append(pill, text);
    if (!caseUrl) { body.before(box); return; }   // not saved (score below 50): no case to open
    const link = document.createElement("a");
    link.href = caseUrl;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = "Details";
    css(link, { color: "#047857", "font-weight": "700", "white-space": "nowrap" });
    box.append(link);
    body.before(box);
  }

  async function check(body) {
    if (!enabled || done.has(body)) return;
    done.add(body);
    const info = readMail(body);
    if (info.text.trim().length < 3) return;
    const answer = await send({ type: "ingestEmail", text: info.text, sender: info.sender, ref: info.ref });
    if (enabled && answer && answer.ok && answer.result) bar(body, answer.result, answer.case_page);
  }

  let timer = null;
  function scan() {
    clearTimeout(timer);
    timer = setTimeout(() => document.querySelectorAll("div.a3s").forEach((b) => {
      if (b.offsetParent !== null && !(b.parentElement && b.parentElement.closest(".a3s"))) check(b);   // visible, outer body only
    }), 500);
  }
  new MutationObserver(() => { if (enabled) scan(); }).observe(document.documentElement, { childList: true, subtree: true });
  chrome.storage.local.get({ enabled: true }, (v) => { enabled = v.enabled !== false; if (enabled) scan(); });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.enabled) return;
    enabled = changes.enabled.newValue !== false;
    if (enabled) { done = new WeakSet(); scan(); }
    else document.querySelectorAll("[data-satark-bar]").forEach((b) => b.remove());
  });
})();
