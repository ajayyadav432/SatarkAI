/* Warning page shown before a link is opened. The link is only followed after the
   user confirms, and never automatically. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const ICON = { Safe: "✓", Low: "i", Medium: "!", High: "!", Critical: "✕" };
  const TITLE = {
    Safe: "No problems found with this link",
    Low: "This link looks mostly fine",
    Medium: "Be careful with this link",
    High: "Warning: this link is probably a scam",
    Critical: "Danger: this link matches known scam patterns",
  };

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function fail(message) {
    $("go-title").textContent = "This link cannot be checked";
    $("go-sub").textContent = message;
    $("go-actions").replaceChildren(backButton());
  }

  function backButton() {
    const b = el("a", "btn primary", "Go back (recommended)");
    b.href = "/";
    b.addEventListener("click", (ev) => {
      if (window.history.length > 1 && document.referrer) { ev.preventDefault(); window.history.back(); }
      else if (window.opener === null && window.history.length <= 1) { ev.preventDefault(); window.close(); location.href = "/"; }
    });
    return b;
  }

  async function main() {
    const raw = new URLSearchParams(location.search).get("u") || "";
    if (!raw) { fail("No link was given."); return; }
    let res, data;
    try {
      res = await fetch("/api/check-url?u=" + encodeURIComponent(raw));
      data = await res.json();
    } catch (e) { fail("The SatarkAI server did not answer."); return; }
    if (!res.ok) { fail(typeof data.detail === "string" ? data.detail : "The link is not valid."); return; }

    $("go-url").textContent = data.display;
    if (!data.valid) { fail("This is not a valid web address."); return; }

    const level = data.level;
    $("go-card").classList.add("risk-" + level);
    $("go-title").textContent = TITLE[level];
    const badge = el("span", "level big lvl-" + level);
    const ico = el("span", "ico", ICON[level]); ico.setAttribute("aria-hidden", "true");
    badge.append(ico, level + " risk · score " + data.score + " / 100");
    $("go-sub").replaceChildren(badge);

    const body = $("go-body");
    body.append(el("p", "", "This link opens the site " + data.registered_domain + "."));
    if (data.factors.length) {
      body.append(el("h3", "", "Why"));
      const ul = el("ul", "url-reasons");
      for (const f of data.factors) {
        const li = el("li");
        li.append(el("b", "", f.title), document.createTextNode(" — " + f.detail));
        ul.append(li);
      }
      body.append(ul);
    } else if (data.trusted) {
      body.append(el("p", "muted", data.notes.length ? data.notes[0].detail : "Official domain."));
    } else {
      body.append(el("p", "muted", "No link tricks were found. This check reads only the address; it cannot see the page itself."));
    }

    const actions = $("go-actions");
    const target = data.url;
    if (!/^https?:\/\//i.test(target)) { fail("Only http and https links can be opened."); return; }
    const go = el("a", "btn", "Open the link anyway");
    go.href = target;
    go.rel = "noopener noreferrer nofollow";
    go.referrerPolicy = "no-referrer";

    if (!data.needs_warning) {
      go.textContent = "Open the link";
      go.classList.add("primary");
      actions.append(go, backButton());
      return;
    }

    // Risky link: opening needs a deliberate confirmation, and for High / Critical a short wait.
    go.setAttribute("aria-disabled", "true");
    const check = document.createElement("input");
    check.type = "checkbox"; check.id = "go-confirm";
    const label = el("label", "check");
    label.append(check, el("span", "", "I understand the risk and still want to open this link"));
    let wait = level === "High" || level === "Critical" ? 5 : 0;
    const update = () => {
      const ready = check.checked && wait <= 0;
      if (ready) go.removeAttribute("aria-disabled"); else go.setAttribute("aria-disabled", "true");
      go.textContent = wait > 0 && check.checked ? "Open the link anyway (" + wait + ")" : "Open the link anyway";
    };
    check.addEventListener("change", () => {
      update();
      if (check.checked && wait > 0) {
        const timer = setInterval(() => { wait -= 1; update(); if (wait <= 0 || !check.checked) clearInterval(timer); }, 1000);
      }
    });
    go.addEventListener("click", (ev) => { if (go.getAttribute("aria-disabled") === "true") ev.preventDefault(); });
    body.append(el("p", "", "Do not enter passwords, OTPs, card or bank details on this site."));
    actions.append(backButton(), label, go);
    update();
  }

  main();
})();
