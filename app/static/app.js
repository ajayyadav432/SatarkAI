/* SatarkAI front end. Plain JavaScript, no build step.
   Security: text from messages is only ever inserted with textContent, never as HTML. */
(function () {
  "use strict";

  // ---------- small helpers ----------
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /** Create an element. Children may be nodes, strings (inserted as text) or null. */
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  /** Create an SVG element (attributes only; no text from messages ever goes in here). */
  function svg(tag, attrs, ...children) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined) continue;
      if (k === "class") el.setAttribute("class", v);
      else if (k === "text") el.textContent = v;
      else el.setAttribute(k, v);
    }
    for (const c of children.flat(Infinity)) if (c) el.append(c);
    return el;
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /** Count a number up from 0 for display only (never used where tests read exact values). */
  function countUp(el, target, suffix, digits) {
    const end = Number(target) || 0, d = digits || 0;
    if (reducedMotion()) { el.textContent = end.toFixed(d) + (suffix || ""); return; }
    const t0 = performance.now(), dur = 900;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / dur), eased = 1 - Math.pow(1 - p, 3);
      el.textContent = (end * eased).toFixed(d) + (suffix || "");
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  async function api(path, options) {
    const res = await fetch(path, options);
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      let msg = "Request failed (" + res.status + ")";
      if (data && data.detail) {
        msg = Array.isArray(data.detail)
          ? data.detail.map((d) => (d.loc ? d.loc[d.loc.length - 1] + ": " : "") + d.msg).join("; ")
          : String(data.detail);
      }
      throw new Error(msg);
    }
    return data;
  }

  let toastTimer = null;
  function toast(message) {
    const el = $("#toast");
    el.textContent = message;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3800);
  }

  const fmtInt = (n) => Number(n || 0).toLocaleString("en-IN");
  const pct = (x, digits) => (x === null || x === undefined ? "n/a" : (100 * x).toFixed(digits === undefined ? 1 : digits) + "%");
  function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return iso || "";
    return d.toLocaleString("en-IN", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  }
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  const LEVELS = ["Safe", "Low", "Medium", "High", "Critical"];
  const LEVEL_ICON = { Safe: "✓", Low: "i", Medium: "!", High: "!", Critical: "✕" };
  const LEVEL_HINT = {
    Safe: "0-19: no scam indicators",
    Low: "20-39: a few weak indicators",
    Medium: "40-59: several indicators, check independently",
    High: "60-79: strong indicators, do not interact",
    Critical: "80-100: matches known scams closely",
  };
  const CHANNEL_LABEL = { sms: "SMS", email: "E-mail", social: "Chat / social", url: "Link", auto: "Auto" };
  const STATUS_LABEL = { new: "New", reviewed: "Reviewed", confirmed_scam: "Confirmed scam", false_positive: "False alarm" };
  const SOURCE_LABEL = {
    "rule": "Language rule", "url-check": "Link check", "ml-text": "Text model", "ml-url": "URL model",
    "impersonation": "Impersonation check", "sender": "Sender check", "live-lookup": "Live lookup",
  };

  function levelBadge(level, big) {
    return h("span", { class: "level lvl-" + level + (big ? " big" : ""), title: LEVEL_HINT[level] || "" },
      h("span", { class: "ico", "aria-hidden": "true" }, LEVEL_ICON[level] || "?"), level);
  }
  const tag = (text) => h("span", { class: "tag", text: text });
  const pill = (text, extra) => h("span", { class: "pill" + (extra ? " " + extra : ""), text: text });

  let META = null;

  // ---------- result rendering (used by Analyze and by the case dialog) ----------

  function highlightedMessage(text, highlights) {
    const box = h("div", { class: "message", tabindex: "0", "aria-label": "Message with suspicious parts highlighted" });
    let pos = 0;
    for (const hl of highlights || []) {
      if (hl.start < pos) continue;
      if (hl.start > pos) box.append(text.slice(pos, hl.start));
      box.append(h("mark", { class: "hl-" + hl.kind, title: hl.label }, text.slice(hl.start, hl.end)));
      pos = hl.end;
    }
    if (pos < text.length) box.append(text.slice(pos));
    return box;
  }

  function meter(score, level) {
    const fill = h("div", { class: "meter-fill bar lvl-" + level });
    fill.style.width = Math.max(1, score) + "%";
    const m = h("div", { class: "meter", role: "img", "aria-label": "Risk score " + score + " out of 100, level " + level }, fill);
    for (const at of [20, 40, 60, 80]) {
      const tick = h("div", { class: "meter-tick" });
      tick.style.left = "calc(" + at + "% - 1px)";
      m.append(tick);
    }
    const scale = h("div", { class: "meter-scale", "aria-hidden": "true" },
      LEVELS.map((l) => h("span", { class: l === level ? "on" : "", text: l })));
    return [m, scale];
  }

  const LEVEL_VAR = { Safe: "--lvl-safe", Low: "--lvl-low", Medium: "--lvl-medium", High: "--lvl-high", Critical: "--lvl-critical" };

  /** Semicircle dial. The arc animates; the number underneath is always the final score. */
  function gauge(score, level) {
    const arc = svg("path", { class: "arc", d: "M14 92 A76 76 0 0 1 166 92", pathLength: "100",
      "stroke-dasharray": "100", "stroke-dashoffset": "100" });
    arc.style.stroke = "var(" + LEVEL_VAR[level] + ")";
    const el = svg("svg", { class: "gauge", viewBox: "0 0 180 104", "aria-hidden": "true" },
      svg("path", { class: "track", d: "M14 92 A76 76 0 0 1 166 92" }), arc);
    // Start the transition once the dial is on the page.
    setTimeout(() => {
      arc.setAttribute("stroke-dashoffset", String(100 - Math.max(1, score)));
    }, 60);
    return el;
  }

  function verdictCard(r, caseId, live) {
    const metaBits = [levelBadge(r.level, true)];
    if (r.category && r.category !== "None") metaBits.push(pill(r.category));
    metaBits.push(pill((CHANNEL_LABEL[r.channel] || r.channel) + (r.channel_detected ? " (detected)" : "")));
    if (caseId) metaBits.push(pill("Case #" + caseId));
    const actions = h("div", { class: "verdict-actions" },
      h("button", { class: "btn small", type: "button", onclick: () => openChat("Why is this rated " + r.level + "?") }, "Ask why"),
      h("button", { class: "btn small", type: "button", onclick: () => copyReport(r) }, "Copy report"));
    return h("div", { class: "card verdict-card v-" + r.level, id: "sec-verdict" },
      h("div", { class: "verdict" },
        h("div", { class: "score-box", role: "img", "aria-label": "Risk score " + r.score + " out of 100" },
          gauge(r.score, r.level),
          h("div", { class: "score-overlay" },
            h("div", { class: "score-num", text: String(r.score) }),
            h("div", { class: "score-of", text: "risk score out of 100" }))),
        h("div", { class: "verdict-main" },
          h("div", { class: "verdict-meta" }, metaBits),
          h("h2", { text: r.summary }),
          meter(r.score, r.level),
          r.elapsed_ms !== undefined ? h("div", { class: "elapsed", text: r.elapsed_ms + " ms · offline" }) : null)),
      h("div", { class: "advice-box" },
        h("h3", { text: "What to do" }),
        h("ul", { class: "advice" }, (r.advice || []).map((a) => h("li", { text: a })))),
      live ? actions : null);
  }

  function copyReport(r) {
    const lines = ["SatarkAI report", "Risk: " + r.level + " (" + r.score + "/100)" + (r.category && r.category !== "None" ? ", " + r.category : ""),
      r.summary, "", "Reasons:"].concat((r.factors || []).map((f) => "- " + f.title + " (+" + f.points + ")"));
    if (r.urls && r.urls.length) lines.push("", "Links (safe form):", ...r.urls.map((u) => "- " + u.display + " : " + u.level));
    lines.push("", "What to do:", ...(r.advice || []).map((a) => "- " + a));
    navigator.clipboard.writeText(lines.join("\n")).then(() => toast("Report copied"), () => toast("Could not copy"));
  }

  /** Buttons that scroll to a result section. Not links: the page uses #hash routing. */
  function jumpNav(r) {
    const go = (id) => () => { const t = document.getElementById(id); if (t) t.scrollIntoView({ behavior: "smooth", block: "start" }); };
    const b = (label, id, n) => h("button", { type: "button", class: "jump-btn", onclick: go(id) }, label, n !== undefined ? h("b", { text: String(n) }) : null);
    const bits = [b("Verdict", "sec-verdict"), b("Message", "sec-message"), b("Why", "sec-why", (r.factors || []).length)];
    if ((r.ml_text && r.ml_text.shap) || (r.urls || []).some((u) => u.ml && u.ml.shap)) bits.push(b("SHAP", "sec-shap"));
    if (r.urls && r.urls.length) bits.push(b("Links", "sec-links", r.urls.length));
    return h("nav", { class: "jump", "aria-label": "Result sections" }, bits);
  }

  function messageCard(r) {
    const kinds = new Set((r.highlights || []).map((x) => x.kind));
    const key = h("div", { class: "hl-key" });
    if (kinds.has("rule")) key.append(h("span", {}, h("mark", { class: "hl-rule", text: "abc" }), " suspicious wording"));
    if (kinds.has("url")) key.append(h("span", {}, h("mark", { class: "hl-url", text: "abc" }), " link"));
    if (kinds.has("brand")) key.append(h("span", {}, h("mark", { class: "hl-brand", text: "abc" }), " organisation named"));
    if (kinds.has("ml")) key.append(h("span", {}, h("mark", { class: "hl-ml", text: "abc" }), " word the text model reacts to"));
    const card = h("div", { class: "card", id: "sec-message" }, h("h3", { text: "Message" }));
    if (r.sender) card.append(h("p", { class: "small muted" }, "Sender: ", tag(r.sender)));
    card.append(highlightedMessage(r.text || "", r.highlights));
    if (kinds.size) card.append(key);
    return card;
  }

  function factorsCard(r) {
    const card = h("div", { class: "card", id: "sec-why" }, h("h3", { text: "Why this level" }));
    if (!r.factors || !r.factors.length) {
      card.append(h("p", { class: "muted", text: "No scam indicators were found in the wording, the links or the sender." }));
      return card;
    }
    const SHOW = 4;
    const more = r.factors.length > SHOW
      ? h("details", { class: "more-factors" }, h("summary", { text: "Show " + (r.factors.length - SHOW) + " more reasons" })) : null;
    r.factors.forEach((f, idx) => {
      const bar = h("i");
      bar.style.width = f.points + "%";
      (idx < SHOW ? card : more).append(h("div", { class: "factor" },
        h("div", { class: "factor-pts" },
          h("b", { text: "+" + f.points }), h("small", { text: "weight" }),
          h("div", { class: "factor-bar" }, bar)),
        h("div", {},
          h("div", { class: "src", text: SOURCE_LABEL[f.source] || f.source }),
          h("h4", { text: f.title }),
          h("p", { text: f.detail }),
          f.evidence && f.evidence.length
            ? h("div", { class: "evidence" }, f.evidence.map((e) => tag(String(e)))) : null)));
    });
    if (more) card.append(more);
    const terms = r.factors.map((f) => "(1 - " + (f.points / 100).toFixed(2) + ")").join(" x ");
    card.append(h("details", {}, h("summary", { text: "How the score is calculated" }), h("div", { class: "formula" },
      "score = 100 x [ 1 - " + terms + " ] = " + (r.cap_applied ? r.score_uncapped + ", limited to " + r.score : r.score))));
    return card;
  }

  function mlUrlDetails(ml) {
    if (!ml || !ml.used) return null;
    const rows = (ml.all_points || []).filter((p) => p.label && Math.abs(p.points) >= 0.05)
      .sort((a, b) => b.points - a.points);
    return h("details", {},
      h("summary", { text: "URL model: " + pct(ml.probability, 0) + " phishing probability (alert from " + pct(ml.threshold, 0) + ")" }),
      h("p", { class: "small muted", text: "Scorecard: every feature adds or removes points. Points are log-odds; start value " + ml.intercept + ", total " + ml.log_odds + "." }),
      h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, h("th", { text: "Feature of this link" }), h("th", { class: "num", text: "Points" }))),
        h("tbody", {}, rows.map((p) => h("tr", {},
          h("td", { text: p.label }), h("td", { class: "num", text: (p.points > 0 ? "+" : "") + p.points.toFixed(2) })))))));
  }

  function lookupBlock(look) {
    if (!look || !look.performed) return null;
    const items = [];
    if (look.dns && look.dns.ok) items.push("DNS: resolves to " + look.dns.addresses.join(", "));
    if (look.rdap && look.rdap.ok && look.rdap.registrar) items.push("Registrar: " + look.rdap.registrar);
    for (const n of look.notes || []) items.push(n);
    if (!items.length) return null;
    return h("div", {}, h("p", { class: "small muted", text: "Live lookup (the link itself was not opened):" }),
      h("ul", { class: "url-reasons" }, items.map((i) => h("li", { text: i }))));
  }

  function linksCard(r) {
    if (!r.urls || !r.urls.length) return null;
    const card = h("div", { class: "card", id: "sec-links" }, h("h3", { text: "Links found (" + r.urls.length + ")" }),
      h("p", { class: "small muted", text: "Shown in a safe, non-clickable form." }));
    for (const u of r.urls) {
      const facts = [];
      if (u.valid) {
        facts.push(pill("Site: " + u.registered_domain));
        if (u.trusted) facts.push(pill(u.official_brand ? "Official domain of " + u.official_brand : "Verified-only registry"));
        if (u.is_shortener) facts.push(pill("Link shortener"));
        if (u.hosting_platform) facts.push(pill("Hosted on " + u.hosting_platform));
        if (u.is_ip) facts.push(pill("IP address"));
        if (u.was_defanged) facts.push(pill("Was disguised"));
      }
      const go = h("a", { class: "btn small", href: "/go?u=" + encodeURIComponent(u.url), target: "_blank", rel: "noopener noreferrer",
        title: "Opens a warning page first" }, u.level === "Safe" || u.level === "Low" ? "Open" : "Open with caution");
      const copy = h("button", { class: "btn small", type: "button", onclick: () => {
        navigator.clipboard.writeText(u.display).then(() => toast("Safe form of the link copied"), () => toast("Could not copy"));
      } }, "Copy safe form");
      card.append(h("div", { class: "url-item" },
        h("div", { class: "url-head" },
          h("span", { class: "url-text", text: u.display }),
          h("span", {}, levelBadge(u.level || "Safe"), " ", h("b", { text: String(u.score) }))),
        h("div", { class: "url-facts" }, facts),
        u.factors && u.factors.length
          ? h("ul", { class: "url-reasons" }, u.factors.map((f) => h("li", {}, h("b", { text: f.title }), " — " + f.detail)))
          : h("p", { class: "small muted", text: u.valid ? (u.trusted ? "Official domain. No link tricks found." : "No link tricks found.") : "This is not a valid link." }),
        lookupBlock(u.lookup),
        mlUrlDetails(u.ml),
        u.valid ? h("div", { class: "url-facts" }, go, copy) : null));
    }
    return card;
  }

  function indicatorsCard(r) {
    const e = r.entities || {};
    const rows = [
      ["Domains", e.domains], ["Phone numbers", e.phones], ["UPI IDs", e.upi_ids],
      ["E-mail addresses", e.emails], ["Money amounts", e.amounts], ["Organisations named", r.brands],
    ].filter((row) => row[1] && row[1].length);
    if (!rows.length) return null;
    return h("div", { class: "card" }, h("h3", { text: "Extracted indicators" }),
      h("dl", { class: "kv" }, rows.map((row) => [h("dt", { text: row[0] }), h("dd", {}, row[1].map((v) => tag(v)))])));
  }

  // ---------- SHAP: how each feature moved the AI model ----------

  const TOKEN_NAME = { urltoken: "a link", emailtoken: "an e-mail address", moneytoken: "a money amount",
    phonetoken: "a phone or long number", numtoken: "a number" };
  const tokenName = (t) => t.split(" ").map((w) => TOKEN_NAME[w] || w).join(" ");
  const signed = (v, d) => (v > 0 ? "+" : v < 0 ? "−" : "") + Math.abs(v).toFixed(d === undefined ? 2 : d);

  /** SHAP waterfall: from the average training example (base value) to this input, one bar per feature. */
  function shapWaterfall(s, title, note) {
    const rows = [];
    let cum = s.base_value;
    const steps = s.features.map((f) => { const from = cum; cum += f.shap; return { f, from, to: cum }; });
    if (Math.abs(s.other.shap) >= 0.005) { const from = cum; cum += s.other.shap; steps.push({ other: true, from, to: cum }); }
    const xs = [s.base_value, s.output_value].concat(...steps.map((x) => [x.from, x.to]));
    const lo = Math.min(...xs), hi = Math.max(...xs), span = (hi - lo) || 1;
    const pos = (v) => (100 * (v - lo) / span);
    const bar = (from, to, cls) => {
      const b = h("i", { class: cls });
      b.style.left = Math.min(pos(from), pos(to)) + "%";
      b.style.width = Math.max(0.6, Math.abs(pos(to) - pos(from))) + "%";
      return h("div", { class: "wf-track" }, b);
    };
    const marker = (v, cls) => { const m = h("i", { class: cls }); m.style.left = pos(v) + "%"; return h("div", { class: "wf-track" }, m); };

    rows.push(h("div", { class: "wf-row wf-end" },
      h("div", { class: "wf-name" }, h("b", { text: "Average example" }), h("small", { text: "base value E[f(x)] · " + pct(s.base_probability, 1) })),
      marker(s.base_value, "wf-dot"), h("div", { class: "wf-val", text: s.base_value.toFixed(2) })));
    for (const st of steps) {
      const v = st.other ? s.other.shap : st.f.shap;
      const name = st.other ? h("span", { class: "muted", text: fmtInt(s.other.count) + " other features" })
        : h("span", {}, st.f.display || tokenName(st.f.feature),
          st.f.present ? null : h("small", { class: "wf-absent", text: " (not in this message)" }));
      rows.push(h("div", { class: "wf-row" }, h("div", { class: "wf-name" }, name),
        bar(st.from, st.to, v >= 0 ? "wf-up" : "wf-down"), h("div", { class: "wf-val " + (v >= 0 ? "up" : "down"), text: signed(v) })));
    }
    rows.push(h("div", { class: "wf-row wf-end" },
      h("div", { class: "wf-name" }, h("b", { text: "This " + (title.includes("Link") ? "link" : "message") }), h("small", { text: "model output f(x) · " + pct(s.probability, 1) })),
      marker(s.output_value, "wf-dot strong"), h("div", { class: "wf-val", text: s.output_value.toFixed(2) })));

    return h("div", { class: "shap-block" },
      h("div", { class: "shap-head" }, h("b", { text: title }), note ? h("span", { class: "muted small", text: note }) : null),
      h("div", { class: "waterfall", role: "img", "aria-label": title + ": SHAP waterfall from " + pct(s.base_probability, 1) + " to " + pct(s.probability, 1) }, rows));
  }

  function shapCard(r) {
    const blocks = [];
    const t = r.ml_text || {};
    if (t.used && t.shap) blocks.push(shapWaterfall(t.shap, "Text model", "trained on " + t.trained_on));
    const u = (r.urls || []).filter((x) => x.ml && x.ml.used && x.ml.shap).sort((a, b) => b.ml.probability - a.ml.probability)[0];
    if (u) blocks.push(shapWaterfall(u.ml.shap, "Link model · " + (u.registered_domain || u.host), null));
    if (!blocks.length) return null;
    return h("div", { class: "card", id: "sec-shap" },
      h("h3", { text: "AI model explanation (SHAP)" }),
      h("p", { class: "small muted", text: "How each feature moved the model from an average training example to this one. " +
        "Red pushes towards scam, green towards safe (log-odds). Exact for our linear models and checked against the shap library." }),
      blocks);
  }

  function notesCard(r) {
    const ml = r.ml_text || {};
    if ((!r.notes || !r.notes.length) && !ml.used) return null;
    const card = h("div", { class: "card" }, h("h3", { text: "Notes" }));
    for (const n of r.notes || []) {
      card.append(h("div", { class: "note" }, h("span", { class: "i", "aria-hidden": "true", text: "i" }),
        h("div", {}, h("b", { text: n.title }), h("span", { text: n.detail }))));
    }
    if (ml.used) {
      const up = ml.scam_terms || [], down = ml.safe_terms || [];
      card.append(h("details", {},
        h("summary", { text: "Text model: " + pct(ml.probability, 0) + " scam probability (trained on " + ml.trained_on + ")" }),
        h("p", { class: "small muted", text: "Linear model. Each word adds or removes points (log-odds); start value " + ml.intercept + ", total " + ml.log_odds + ". " + pct(ml.known_word_share, 0) + " of the words are known to the model." }),
        h("div", { class: "two-col" },
          h("div", {}, h("p", { class: "small", text: "Pushes towards scam" }),
            h("div", { class: "term-list" }, up.length ? up.map((t) => tag(t.display + "  +" + t.contribution.toFixed(2))) : h("span", { class: "muted small", text: "none" }))),
          h("div", {}, h("p", { class: "small", text: "Pushes towards safe" }),
            h("div", { class: "term-list" }, down.length ? down.map((t) => tag(t.display + "  " + t.contribution.toFixed(2))) : h("span", { class: "muted small", text: "none" }))))));
    }
    return card;
  }

  /** live: the result on the Analyze page (gets the jump bar and the assistant buttons). */
  function renderResult(r, caseId, live) {
    return [live ? jumpNav(r) : null, verdictCard(r, caseId, live), messageCard(r), factorsCard(r), shapCard(r), linksCard(r),
      indicatorsCard(r), notesCard(r)].filter(Boolean);
  }

  // ---------- step-by-step scan ----------

  const PIPELINE = [
    { title: "Reading the message", hint: "Pull out links, phone numbers, UPI IDs and amounts" },
    { title: "Checking every link", hint: "Lookalike domains, brand names on other domains, shorteners" },
    { title: "Reading the wording", hint: "Urgency, threats, rewards, requests for secrets (EN / Hinglish / Hindi)" },
    { title: "Checking sender and organisations", hint: "Is a bank or company being impersonated?" },
    { title: "Asking the AI models", hint: "Text model and URL model, trained on public datasets" },
    { title: "Combining the evidence", hint: "One score from 0 to 100 and a risk level" },
  ];
  const HIGH = new Set(["High", "Critical"]);
  const plural = (n, one, many) => n + " " + (n === 1 ? one : (many || one + "s"));

  /** What each pipeline stage found, taken from the real result. Returns [text, isWarning]. */
  function stageFindings(r) {
    const e = r.entities || {}, f = r.factors || [];
    const bySrc = (...src) => f.filter((x) => src.includes(x.source));
    const found = [plural((r.urls || []).length, "link"), plural((e.phones || []).length, "phone number"),
      plural((e.upi_ids || []).length, "UPI ID")];
    const out = [[(CHANNEL_LABEL[r.channel] || r.channel) + ": " + found.join(", "), false]];

    const urls = (r.urls || []).slice().sort((a, b) => b.score - a.score);
    out.push(urls.length
      ? [(urls[0].registered_domain || urls[0].display) + " → " + urls[0].level + (urls.length > 1 ? " (worst of " + urls.length + ")" : ""), HIGH.has(urls[0].level)]
      : ["No links in the message", false]);

    const rules = bySrc("rule");
    out.push(rules.length
      ? [plural(rules.length, "warning pattern") + ": " + rules.slice(0, 2).map((x) => x.title).join(", ") + (rules.length > 2 ? "…" : ""), true]
      : ["No scam wording found", false]);

    const imp = bySrc("sender", "impersonation");
    out.push(imp.length ? [imp[0].title, true]
      : [(r.brands || []).length ? "Names " + r.brands.join(", ") + ", no impersonation sign" : "No organisation named", false]);

    const ml = [];
    let mlWarn = false;
    if (r.ml_text && r.ml_text.used) { ml.push("text " + pct(r.ml_text.probability, 0) + " scam"); mlWarn = mlWarn || r.ml_text.probability >= 0.5; }
    const urlMl = urls.filter((u) => u.ml && u.ml.used).map((u) => u.ml.probability);
    if (urlMl.length) { const p = Math.max(...urlMl); ml.push("link " + pct(p, 0) + " phishing"); mlWarn = mlWarn || bySrc("ml-url").length > 0; }
    out.push(ml.length ? ["Models: " + ml.join(", "), mlWarn] : ["Models not used for this message (see Notes)", false]);

    out.push(["Score " + r.score + " → " + r.level + (f.length ? " from " + plural(f.length, "indicator") : ""), HIGH.has(r.level)]);
    return out;
  }

  function pipelineList(withFindings) {
    return PIPELINE.map((s, i) => h("li", { class: withFindings ? "step-row" : "" },
      h("span", { class: "num", text: String(i + 1) }),
      h("span", {}, h("b", { text: s.title }), h("small", { class: withFindings ? "finding" : "", text: s.hint }))));
  }

  /** Shows the six stages one by one with what each found. The analysis itself already finished. */
  async function playScan(out, r) {
    const rows = pipelineList(true);
    const bar = h("i");
    let skipped = false;
    const skip = h("button", { type: "button", class: "btn small", onclick: () => { skipped = true; } }, "Skip");
    out.replaceChildren(h("div", { class: "card scan-card" },
      h("div", { class: "scan-head" }, h("h2", {}, h("span", { class: "radar", "aria-hidden": "true" }), "Scanning"), skip),
      h("div", { class: "scan-progress" }, bar),
      h("ol", { class: "pipeline scan-steps" }, rows),
      h("p", { class: "scan-note", text: "Done in " + r.elapsed_ms + " ms · slowed down so you can follow" })));
    const findings = stageFindings(r);
    for (let i = 0; i < rows.length && !skipped; i++) {
      rows[i].classList.add("active");
      await sleep(330);
      rows[i].classList.remove("active");
      rows[i].classList.add("done");
      if (findings[i][1]) rows[i].classList.add("warn");
      $(".finding", rows[i]).textContent = findings[i][0];
      $(".num", rows[i]).textContent = findings[i][1] ? "!" : "✓";
      bar.style.width = (100 * (i + 1) / rows.length) + "%";
      await sleep(110);
    }
    if (!skipped) await sleep(350);
  }

  // ---------- Analyze view ----------

  let lastScan = null;   // {text, channel, sender} of the last analysis, for the assistant

  async function loadHeroStats() {
    const host = $("#hero-stats");
    const tile = (label, note) => {
      const b = h("b", { text: "–" });
      host.append(h("div", { class: "hstat", title: note || "" }, b, h("span", { text: label })));
      return b;
    };
    try {
      const [s, card] = await Promise.all([api("/api/stats?days=90"), api("/api/model-card")]);
      const k = s.kpis;
      host.replaceChildren();
      countUp(tile("checked", "Last 90 days" + (k.demo ? ", including " + k.demo + " demo cases" : "")), k.total);
      countUp(tile("high-risk", k.high_risk_share + "% rated High or Critical, last 90 days"), k.high_risk);
      const m = card.metrics;
      if (m) countUp(tile("accuracy", "Text model on held-out SMS test set"), 100 * m.text_model.channels.sms.test.accuracy, "%", 1);
    } catch (err) { host.hidden = true; }
  }

  /** Fill in versions and sizes of the downloads; disable the app button if the APK is not built. */
  async function loadDownloads() {
    const mb = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
    $("#copy-ext-url").addEventListener("click", () => {
      navigator.clipboard.writeText("chrome://extensions").then(() => toast("Copied. Paste it into the address bar."), () => toast("Could not copy"));
    });
    let d;
    try { d = await api("/api/downloads"); } catch (e) { return; }
    const ext = d.extension;
    $("#ext-meta").textContent = "Version " + ext.version + " · " + mb(ext.size) + " · Chrome and Edge";
    const apk = d.apk, btn = $("#apk-btn");
    if (apk.available) {
      $("#apk-meta").textContent = "Version " + (apk.version || "?") + " · " + mb(apk.size) + " · Android 8 or newer";
    } else {
      btn.removeAttribute("href");
      btn.setAttribute("aria-disabled", "true");
      btn.textContent = "Not built yet";
      $("#apk-meta").textContent = "Build it first: " + apk.build;
    }
  }

  function initAnalyze() {
    const form = $("#analyze-form"), text = $("#text"), counter = $("#char-count");
    const updateCount = () => { counter.textContent = fmtInt(text.value.length); };
    text.addEventListener("input", updateCount);

    const fast = $("#opt-fast");
    try { fast.checked = localStorage.getItem("satark-fast") === "1"; } catch (e) { /* ignore */ }
    fast.addEventListener("change", () => { try { localStorage.setItem("satark-fast", fast.checked ? "1" : "0"); } catch (e) { /* ignore */ } });

    $("#paste-btn").addEventListener("click", async () => {
      try { text.value = await navigator.clipboard.readText(); updateCount(); text.focus(); }
      catch (e) { toast("The browser blocked clipboard access. Press Ctrl+V in the box instead."); text.focus(); }
    });
    loadHeroStats();
    loadDownloads();

    async function run() {
      const body = {
        text: text.value,
        channel: (form.querySelector("input[name=channel]:checked") || {}).value || "auto",
        sender: $("#sender").value.trim() || null,
        save: $("#opt-save").checked,
        lookup: $("#opt-lookup").checked,
      };
      if (!body.text.trim()) { toast("Paste a message or a link first."); text.focus(); return; }
      const btn = $("#analyze-btn");
      btn.disabled = true; btn.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), "Analyzing…");
      try {
        const r = await api("/api/analyze", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        const out = $("#result");
        const reveal = () => {   // bring the top of the result column into view
          const top = out.getBoundingClientRect().top;
          if (top < 70 || top > window.innerHeight * 0.5) window.scrollTo({ top: window.scrollY + top - 84, behavior: "smooth" });
        };
        if (!$("#opt-fast").checked && !reducedMotion()) { const scan = playScan(out, r); reveal(); await scan; }
        lastScan = { text: body.text, channel: body.channel, sender: body.sender, level: r.level };
        out.replaceChildren(...renderResult(r, r.case_id, true));
        reveal();
        refreshChatSuggestions();
      } catch (err) {
        toast(err.message);
      } finally {
        btn.disabled = false; btn.textContent = "Analyze";
      }
    }

    form.addEventListener("submit", (ev) => { ev.preventDefault(); run(); });
    text.addEventListener("keydown", (ev) => { if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) run(); });
    $("#clear-btn").addEventListener("click", () => {
      text.value = ""; $("#sender").value = ""; updateCount();
      form.querySelector("input[name=channel][value=auto]").checked = true;
      text.focus();
    });

    const list = $("#sample-list");
    for (const s of META.samples) {
      list.append(h("button", { type: "button", class: "chip", title: s.kind === "scam" ? "Scam example" : "Genuine example",
        onclick: () => {
          text.value = s.text; $("#sender").value = s.sender || ""; updateCount();
          const radio = form.querySelector("input[name=channel][value=" + s.channel + "]");
          if (radio) radio.checked = true;
          run();
        } }, h("span", { class: "dot " + s.kind, "aria-hidden": "true" }), s.label,
        h("span", { class: "muted small", text: s.kind === "scam" ? "scam" : "genuine" })));
    }
    $("#level-legend").replaceChildren(...LEVELS.map((l) => h("li", {}, levelBadge(l))));
  }

  // ---------- History view ----------

  const hist = { page: 1 };

  function historyParams() {
    const p = new URLSearchParams();
    const add = (k, v) => { if (v) p.set(k, v); };
    add("q", $("#f-q").value.trim());
    add("level", $("#f-level").value);
    add("category", $("#f-category").value);
    add("status", $("#f-status").value);
    add("channel", $("#f-channel").value);
    add("date_from", $("#f-from").value);
    add("date_to", $("#f-to").value);
    return p;
  }

  async function loadHistory() {
    const p = historyParams();
    $("#export-btn").href = "/api/cases/export.csv" + (p.toString() ? "?" + p.toString() : "");
    p.set("sort", $("#f-sort").value);
    p.set("page", String(hist.page));
    p.set("page_size", "15");
    let data;
    try { data = await api("/api/cases?" + p.toString()); }
    catch (err) { toast(err.message); return; }

    const catSel = $("#f-category"), current = catSel.value;
    catSel.replaceChildren(h("option", { value: "", text: "All" }),
      ...data.categories.map((c) => h("option", { value: c, text: c })));
    catSel.value = data.categories.includes(current) ? current : "";

    const body = $("#history-table tbody");
    if (!data.items.length) {
      body.replaceChildren(h("tr", { class: "empty-row" }, h("td", { colspan: "7",
        text: data.total === 0 && !p.get("q") ? "No cases match. Analyse a message to create the first case." : "No cases match these filters." })));
    } else {
      body.replaceChildren(...data.items.map((c) => {
        const open = () => openCase(c.id);
        return h("tr", { class: "clickable", tabindex: "0", onclick: open,
          onkeydown: (ev) => { if (ev.key === "Enter") open(); } },
          h("td", { class: "num", text: String(c.id) }),
          h("td", { class: "nowrap", text: fmtTime(c.created_at) }),
          h("td", { class: "nowrap" }, levelBadge(c.level), " ", h("b", { text: String(c.score) })),
          h("td", {}, c.category === "None" ? h("span", { class: "muted", text: "—" }) : c.category),
          h("td", {}, h("div", { class: "msg", text: c.text }),
            c.source !== "user" ? pill(c.source, c.source === "demo-seed" ? "demo" : "") : null),
          h("td", { class: "nowrap", text: CHANNEL_LABEL[c.channel] || c.channel }),
          h("td", { class: "nowrap", text: STATUS_LABEL[c.status] || c.status }));
      }));
    }
    $("#history-count").textContent = fmtInt(data.total) + (data.total === 1 ? " case" : " cases");
    const prev = h("button", { class: "btn small", type: "button", disabled: data.page <= 1,
      onclick: () => { hist.page -= 1; loadHistory(); } }, "Previous");
    const next = h("button", { class: "btn small", type: "button", disabled: data.page >= data.pages,
      onclick: () => { hist.page += 1; loadHistory(); } }, "Next");
    $("#pager").replaceChildren(h("span", { class: "muted small", text: "Page " + data.page + " of " + data.pages }), prev, next);
  }

  function initHistory() {
    const fill = (sel, values, labels) => {
      for (const v of values) $(sel).append(h("option", { value: v, text: (labels && labels[v]) || v }));
    };
    fill("#f-level", LEVELS);
    fill("#f-status", META.statuses, STATUS_LABEL);
    fill("#f-channel", META.channels, CHANNEL_LABEL);

    let timer = null;
    const refresh = () => { hist.page = 1; loadHistory(); };
    $("#f-q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(refresh, 250); });
    for (const id of ["#f-level", "#f-category", "#f-status", "#f-channel", "#f-from", "#f-to", "#f-sort"]) {
      $(id).addEventListener("change", refresh);
    }
    $("#filter-form").addEventListener("submit", (ev) => { ev.preventDefault(); refresh(); });
    $("#f-reset").addEventListener("click", () => { $("#filter-form").reset(); refresh(); });

    $("#bulk-file").addEventListener("change", async (ev) => {
      const file = ev.target.files[0];
      if (!file) return;
      const fd = new FormData();
      fd.append("file", file);
      toast("Analysing " + file.name + "...");
      try {
        const r = await api("/api/bulk", { method: "POST", body: fd });
        const high = r.by_level.High + r.by_level.Critical;
        toast(r.analysed + " messages analysed, " + high + " high-risk" + (r.truncated ? " (file cut at " + r.max_rows + " rows)" : ""));
        refresh();
      } catch (err) { toast(err.message); }
      ev.target.value = "";
    });
  }

  // ---------- Case dialog ----------

  async function openCase(id) {
    let c;
    try { c = await api("/api/cases/" + id); } catch (err) { toast(err.message); return; }
    $("#case-title").textContent = "Case #" + c.id + " · " + fmtTime(c.created_at);
    const status = h("select", { id: "case-status" },
      META.statuses.map((s) => h("option", { value: s, text: STATUS_LABEL[s] || s, selected: s === c.status })));
    const notes = h("input", { type: "text", id: "case-notes", maxlength: "2000", value: c.notes || "", placeholder: "Analyst notes" });
    const save = h("button", { class: "btn primary", type: "button", onclick: async () => {
      try {
        await api("/api/cases/" + c.id, { method: "PATCH", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: status.value, notes: notes.value }) });
        toast("Case #" + c.id + " updated");
        loadHistory();
      } catch (err) { toast(err.message); }
    } }, "Save");
    const del = h("button", { class: "btn danger", type: "button", onclick: async () => {
      if (!window.confirm("Delete case #" + c.id + "? This cannot be undone.")) return;
      try {
        await api("/api/cases/" + c.id, { method: "DELETE" });
        $("#case-dialog").close();
        toast("Case #" + c.id + " deleted");
        loadHistory();
      } catch (err) { toast(err.message); }
    } }, "Delete");
    const admin = h("div", { class: "card" }, h("h3", { text: "Analyst review" }),
      c.source !== "user" ? h("p", { class: "small muted" }, "Source: ", pill(c.source, c.source === "demo-seed" ? "demo" : "")) : null,
      h("div", { class: "case-admin" },
        h("label", { class: "field" }, h("span", { text: "Status" }), status),
        h("label", { class: "field" }, h("span", { text: "Notes" }), notes),
        h("div", { class: "actions" }, save, del)));
    $("#case-body").replaceChildren(admin, ...renderResult(c.result, null));
    const dlg = $("#case-dialog");
    if (!dlg.open) dlg.showModal();
    dlg.scrollTop = 0;
  }

  // ---------- Dashboard ----------

  let trendChart = null;
  let lastStats = null;

  function barList(items, opts) {
    // items: [{name, value, node?, level?}]
    if (!items.length) return h("div", { class: "empty-chart", text: opts.empty || "No data in this period." });
    const max = Math.max(...items.map((i) => i.value), 1);
    return h("div", { class: "barlist", role: "list" }, items.map((i) => {
      const bar = h("div", { class: "bar" + (i.level ? " lvl-" + i.level : "") });
      bar.style.width = (100 * i.value / max) + "%";
      return h("div", { class: "row", role: "listitem", title: i.name + ": " + fmtInt(i.value) + (opts.unit ? " " + opts.unit : "") },
        h("div", { class: "name" }, i.node || i.name),
        h("div", { class: "val", text: fmtInt(i.value) }),
        h("div", { class: "track" }, bar));
    }));
  }

  function chartCard(title, sub, body) {
    return h("div", { class: "card chart-card" }, h("h2", { text: title }), sub ? h("div", { class: "sub", text: sub }) : null, body);
  }

  /** Donut of cases per risk level, drawn as SVG circles (one segment per level). */
  function donut(levels, total) {
    const segs = [];
    let at = 0;
    for (const l of levels) {
      if (!l.n) continue;
      const share = 100 * l.n / total;
      const c = svg("circle", { class: "seg", cx: "85", cy: "85", r: "62", pathLength: "100",
        "stroke-dasharray": share.toFixed(3) + " " + (100 - share).toFixed(3),
        "stroke-dashoffset": String(25 - at) }, svg("title", { text: l.level + ": " + l.n + " cases (" + share.toFixed(0) + "%)" }));
      c.style.stroke = "var(" + LEVEL_VAR[l.level] + ")";
      segs.push(c);
      at += share;
    }
    return svg("svg", { class: "donut", viewBox: "0 0 170 170", role: "img", "aria-label": "Cases by risk level" },
      svg("circle", { class: "donut-bg", cx: "85", cy: "85", r: "62" }), segs,
      svg("text", { class: "big", x: "85", y: "88", text: fmtInt(total) }),
      svg("text", { class: "lbl", x: "85", y: "106", text: "cases" }));
  }

  function threatCard(s) {
    const top = s.categories[0];
    if (!top) return null;
    const bits = [plural(top.n, "case") + " in the last " + s.days + " days, average risk " + Math.round(top.avg_score) + "/100."];
    if (s.brands[0]) bits.push("Most impersonated: " + s.brands[0].brand + " (" + s.brands[0].n + ").");
    if (s.factors[0]) bits.push("Most common sign: " + s.factors[0].title + ".");
    return h("div", { class: "card threat-card" },
      h("div", { class: "threat-ico", "aria-hidden": "true", text: "⚠" }),
      h("div", {}, h("div", { class: "eyebrow-sm", text: "Top threat this period" }),
        h("h2", { text: top.category }), h("p", { text: bits.join(" ") })));
  }

  function kpi(label, value, sub, hero, extra) {
    return h("div", { class: "card kpi" + (hero ? " hero" : "") + (extra ? " " + extra : "") },
      h("div", { class: "label", text: label }), h("div", { class: "value", text: value }),
      sub ? h("div", { class: "sub", text: sub }) : null);
  }

  function drawTrend(canvas, s) {
    const high = s.trend.days.map((_, i) => s.trend.series.High[i] + s.trend.series.Critical[i]);
    const other = s.trend.days.map((_, i) => s.trend.series.Safe[i] + s.trend.series.Low[i] + s.trend.series.Medium[i]);
    const labels = s.trend.days.map((d) => new Date(d + "T00:00:00").toLocaleDateString("en-IN", { day: "numeric", month: "short" }));
    const surface = cssVar("--surface"), muted = cssVar("--muted"), ink = cssVar("--ink");
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(canvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          { label: "Safe, Low or Medium", data: other, backgroundColor: cssVar("--neutral-bar"),
            borderColor: surface, borderWidth: { top: 2, right: 0, bottom: 0, left: 0 }, borderRadius: 4 },
          { label: "High or Critical", data: high, backgroundColor: cssVar("--lvl-critical"), borderRadius: 4 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        datasets: { bar: { maxBarThickness: 24, categoryPercentage: 0.72, barPercentage: 0.9 } },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: ink, titleColor: surface, bodyColor: surface, padding: 10, boxWidth: 10, boxHeight: 2,
            callbacks: { footer: (items) => "Total: " + items.reduce((a, it) => a + it.parsed.y, 0) },
            footerColor: surface,
          },
        },
        scales: {
          x: { stacked: true, grid: { display: false }, border: { color: cssVar("--axis") },
               ticks: { color: muted, maxRotation: 0, autoSkip: true, maxTicksLimit: 8, font: { family: cssVar("--font") } } },
          y: { stacked: true, beginAtZero: true, border: { display: false }, grid: { color: cssVar("--hairline") },
               ticks: { color: muted, precision: 0, maxTicksLimit: 6, font: { family: cssVar("--font") } } },
        },
      },
    });
    return { labels, high, other };
  }

  function renderDashboard(s) {
    lastStats = s;
    const k = s.kpis, body = $("#dashboard-body");
    const demo = $("#demo-flag");
    demo.hidden = !k.demo;
    if (k.demo) demo.textContent = "Includes " + fmtInt(k.demo) + " demo cases";
    $("#dash-sub").textContent = fmtInt(k.total_all_time) + " cases in total";

    const kpis = h("div", { class: "kpis" },
      kpi("Cases", fmtInt(k.total), "last " + s.days + " days", true),
      kpi("High or Critical", fmtInt(k.high_risk), k.high_risk_share + "%", false, k.high_risk ? "alert" : ""),
      kpi("To review", fmtInt(k.needs_review), ""),
      kpi("Today", fmtInt(k.today), ""),
      kpi("Avg. score", String(k.avg_score), ""),
      kpi("Analyst verdicts", fmtInt(k.confirmed) + " / " + fmtInt(k.false_positives), "confirmed / false alarm"));

    const canvas = h("canvas", { role: "img", "aria-label": "Cases per day, high-risk cases against all other cases" });
    const legend = h("div", { class: "chart-legend" });
    const tableHost = h("div");
    const trendCard = chartCard("Cases per day", "",
      [legend, h("div", { class: "chart-box" }, canvas), tableHost]);

    const levelItems = s.levels.map((l) => ({ name: l.level, value: l.n, level: l.level, node: levelBadge(l.level) }));
    const levelsCard = chartCard("Risk levels", "",
      k.total ? h("div", { class: "donut-wrap" }, donut(s.levels, k.total), barList(levelItems, { unit: "cases" }))
        : h("div", { class: "empty-chart", text: "No cases in this period." }));

    const cats = chartCard("Scam categories", "",
      barList(s.categories.map((c) => ({ name: c.category, value: c.n })), { unit: "cases", empty: "No scam categories yet." }));
    const facts = chartCard("Most common warning signs", "",
      barList(s.factors.map((f) => ({ name: f.title, value: f.n })), { unit: "cases", empty: "No indicators yet." }));
    const brandsCard = chartCard("Impersonated organisations", "Medium risk or higher",
      barList(s.brands.map((b) => ({ name: b.brand, value: b.n })), { unit: "cases", empty: "No organisations named yet." }));

    const domains = chartCard("Suspicious domains", "Medium risk or higher",
      s.domains.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, h("th", { text: "Domain" }), h("th", { class: "num", text: "Cases" }),
          h("th", { class: "num", text: "Top score" }))),
        h("tbody", {}, s.domains.map((d) => h("tr", { title: "Last seen " + fmtTime(d.last_seen) },
          h("td", {}, h("span", { class: "mono", text: d.domain.replace(/\./g, "[.]") })),
          h("td", { class: "num", text: String(d.n) }), h("td", { class: "num", text: String(d.max_score) }))))))
        : h("div", { class: "empty-chart", text: "No suspicious domains yet." }));

    const recent = chartCard("Latest high-risk cases", "",
      s.recent_high_risk.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, h("th", { text: "Risk" }), h("th", { text: "Category and message" }))),
        h("tbody", {}, s.recent_high_risk.map((c) => h("tr", { class: "clickable", tabindex: "0",
          onclick: () => openCase(c.id), onkeydown: (ev) => { if (ev.key === "Enter") openCase(c.id); } },
          h("td", { class: "nowrap" }, levelBadge(c.level), " ", h("b", { text: String(c.score) })),
          h("td", {}, h("b", { text: c.category }), h("div", { class: "clamp muted small", text: c.text })))))))
        : h("div", { class: "empty-chart", text: "No high-risk cases in this period." }));

    const channels = chartCard("By message type", "",
      s.channels.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, h("th", { text: "Type" }), h("th", { class: "num", text: "Cases" }), h("th", { class: "num", text: "High-risk" }))),
        h("tbody", {}, s.channels.map((c) => h("tr", {},
          h("td", { text: CHANNEL_LABEL[c.channel] || c.channel }), h("td", { class: "num", text: fmtInt(c.n) }),
          h("td", { class: "num", text: fmtInt(c.high_risk) }))))))
        : h("div", { class: "empty-chart", text: "No cases in this period." }));

    body.replaceChildren(kpis, threatCard(s) || "",
      h("div", { class: "dash-row" }, trendCard, levelsCard),
      h("div", { class: "dash-row" }, cats, facts, brandsCard),
      h("div", { class: "dash-row" }, domains, recent, channels));

    const t = drawTrend(canvas, s);
    const sw = (color) => { const i = h("i"); i.style.background = color; return i; };
    legend.replaceChildren(
      h("span", {}, sw(cssVar("--lvl-critical")), "High or Critical"),
      h("span", {}, sw(cssVar("--neutral-bar")), "Safe, Low or Medium"));
    tableHost.replaceChildren(h("details", {}, h("summary", { text: "View as table" }),
      h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, h("th", { text: "Day" }), h("th", { class: "num", text: "High or Critical" }),
          h("th", { class: "num", text: "Safe, Low or Medium" }))),
        h("tbody", {}, t.labels.map((d, i) => h("tr", {}, h("td", { text: d }),
          h("td", { class: "num", text: String(t.high[i]) }), h("td", { class: "num", text: String(t.other[i]) }))))))));
  }

  async function loadDashboard() {
    const days = (document.querySelector("input[name=range]:checked") || {}).value || "30";
    const body = $("#dashboard-body");
    body.classList.add("loading");   // keep the previous render while new data loads
    try { renderDashboard(await api("/api/stats?days=" + days)); }
    catch (err) { toast(err.message); }
    finally { body.classList.remove("loading"); }
  }

  // ---------- How it works ----------

  let aboutLoaded = false;

  function metricTiles(m) {
    const items = [
      ["Accuracy", pct(m.accuracy)], ["Precision", pct(m.precision)], ["Recall", pct(m.recall)],
      ["F1 score", pct(m.f1)], ["False alarms", pct(m.false_positive_rate)],
    ];
    if (m.roc_auc !== undefined) items.push(["ROC AUC", m.roc_auc.toFixed(3)]);
    return h("div", { class: "metric-grid" }, items.map((it) =>
      h("div", { class: "metric" }, h("div", { class: "label", text: it[0] }), h("div", { class: "value", text: it[1] }))));
  }

  function confusion(m) {
    const c = m.confusion;
    return h("p", { class: "small muted", text:
      "Held-out test set: " + fmtInt(m.n) + " items (" + fmtInt(m.n_scam) + " scam). Scams caught " + fmtInt(c.tp) +
      ", scams missed " + fmtInt(c.fn) + ", genuine passed " + fmtInt(c.tn) + ", genuine wrongly flagged " + fmtInt(c.fp) +
      ". Always answering the majority class would score " + pct(m.majority_class_accuracy) + "." });
  }

  function simpleTable(head, rows) {
    return h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, head.map((t, i) => h("th", { class: i ? "num" : "", text: t })))),
      h("tbody", {}, rows.map((r) => h("tr", {}, r.map((v, i) => h("td", { class: i ? "num" : "", text: String(v) })))))));
  }

  function renderAbout(card) {
    const host = $("#about-body");
    const M = card.metrics;
    const nodes = [];

    nodes.push(h("div", { class: "card" }, h("h2", { text: "What happens to a message" }),
      h("div", { class: "steps" },
        h("div", { class: "step" }, h("b", { text: "Extract" }), h("p", { text: "Links (also disguised ones such as hxxp:// and example[.]com), phone numbers, UPI IDs, e-mail addresses and amounts are pulled out." })),
        h("div", { class: "step" }, h("b", { text: "Check every link" }), h("p", { text: "Known tricks: lookalike domains, a brand name on someone else's domain, IP addresses, shorteners, app downloads. The link is never opened." })),
        h("div", { class: "step" }, h("b", { text: "Read the wording" }), h("p", { text: card.rules.length + " rule groups for urgency, threats, rewards, requests for secrets and more, in English, Hinglish and Hindi." })),
        h("div", { class: "step" }, h("b", { text: "Ask the models" }), h("p", { text: "A text model and a URL model, both linear, so each word or feature has an exact, visible contribution." })),
        h("div", { class: "step" }, h("b", { text: "Combine" }), h("p", { text: "All evidence is combined into one score from 0 to 100, a level and a scam category." })),
        h("div", { class: "step" }, h("b", { text: "Warn and record" }), h("p", { text: "Risky links open only through a warning page. Each case is stored in a searchable history." })))));

    const sc = card.scoring;
    nodes.push(h("div", { class: "card" }, h("h2", { text: "How the score is calculated" }),
      h("div", { class: "formula", text: sc.formula }),
      h("p", { class: "small", text: "Every piece of evidence has a weight between 0 and 1. One weak signal gives a low score, independent signals add up, and extra evidence can never lower the score." }),
      h("ul", { class: "legend-levels" }, LEVELS.map((l) => h("li", {}, levelBadge(l), h("span", { class: "muted small", text: LEVEL_HINT[l] })))),
      h("p", { class: "small muted", text:
        "Rule and link-check weights are set by hand. A model's weight grows with its probability: text model " +
        sc.text_model_weight["at_probability_0.5"] + " to " + sc.text_model_weight["at_probability_1.0"] + ", URL model " +
        sc.url_model_weight.at_threshold + " to " + sc.url_model_weight["at_probability_1.0"] +
        ". So a model alone can reach Medium at most." }),
      h("p", { class: "small muted", text: sc.cap.reason })));

    if (!M) {
      nodes.push(h("div", { class: "card" }, h("h2", { text: "Models are not trained yet" }),
        h("p", { text: "Run ./run.sh train to download the datasets and train the models. Rules and link checks work without them." })));
      host.replaceChildren(...nodes);
      return;
    }

    // Text models
    const T = M.text_model;
    const textCards = Object.entries(T.channels).map(([name, c]) => {
      const o = c.tested_on_other_channel;
      return h("div", { class: "card" },
        h("h2", { text: (name === "sms" ? "Text model for SMS and chat" : "Text model for e-mail") }),
        h("p", { class: "small muted", text: "Trained on " + fmtInt(c.train_rows) + " messages, " + fmtInt(c.n_features) + " word features. Tested on " + fmtInt(c.test_rows) + " messages it never saw." }),
        metricTiles(c.test), confusion(c.test),
        h("p", { class: "small", text: "The same model on the other channel (" + (o.channel === "sms" ? "SMS" : "e-mail") + "): accuracy " + pct(o.accuracy) +
          ", false alarms " + pct(o.false_positive_rate) + ". It does not transfer, which is why each channel has its own model." }),
        h("p", { class: "small", text: "Vocabulary check: the model is used only when at least " + pct(c.gate.min_known_fraction, 0) +
          " of a message's words are known to it. " + pct(c.gate.test_messages_passing_gate) + " of test messages pass. Otherwise it is skipped and the user is told." }),
        h("details", {}, h("summary", { text: "Words with the strongest learned weights" }),
          h("p", { class: "small", text: "Towards scam" }), h("div", { class: "term-list" }, c.top_scam_terms.slice(0, 24).map((t) => tag(t.term))),
          h("p", { class: "small", text: "Towards safe" }), h("div", { class: "term-list" }, c.top_safe_terms.slice(0, 24).map((t) => tag(t.term)))));
    });
    nodes.push(h("div", { class: "card" }, h("h2", { text: "Text models" }),
      h("p", { text: T.algorithm + ". " + T.why }),
      h("p", { class: "small muted", text: "Split: " + T.split + ". Decision threshold " + T.threshold + "." })));
    nodes.push(h("div", { class: "two-col" }, textCards));

    // URL model
    const U = M.url_model, S = U.sanity;
    const srcName = { all: "All test URLs", phiusiil_domains: "Domains (PhiUSIIL)", web_page_phishing: "Full URLs (web page dataset)" };
    const urlRows = Object.entries(U.test).map(([k, m]) => [srcName[k] || k, fmtInt(m.n), pct(m.accuracy), pct(m.precision), pct(m.recall), pct(m.false_positive_rate), m.roc_auc]);
    const bbRows = Object.entries(U.black_box_comparison.test).map(([k, m]) => [srcName[k] || k, pct(m.accuracy), pct(U["test_at_0.5"][k].accuracy), m.roc_auc, U.test[k].roc_auc]);
    const legit = S.hand_written_legitimate_urls, feed = S.openphish_feed;
    nodes.push(h("div", { class: "card" }, h("h2", { text: "URL model" }),
      h("p", { text: U.algorithm + ". " + U.why }),
      h("p", { class: "small muted", text: "Reads only the text of the link. Trained on " + fmtInt(U.train_rows) + " URLs, tested on " + fmtInt(U.test_rows) + ". Split: " + U.split + "." }),
      metricTiles(U.test.all), confusion(U.test.all),
      h("p", { class: "small", text: "Alert threshold " + U.threshold + ": " + U.threshold_rule + ". This trades recall for few false alarms; the link checks and wording rules cover what the model misses." }),
      simpleTable(["Test set", "URLs", "Accuracy", "Precision", "Recall", "False alarms", "ROC AUC"], urlRows),
      h("h3", { text: "Extra checks" }),
      h("ul", { class: "limits" },
        h("li", { text: "Well-known legitimate links typed by hand: " + legit.flagged_as_phishing + " of " + legit.n + " wrongly flagged" +
          (legit.flagged.length ? " (" + legit.flagged.map((f) => f.url).join(", ") + ")." : ".") }),
        feed.skipped
          ? h("li", { text: "Live phishing feed (OpenPhish): skipped, the feed could not be downloaded." })
          : h("li", { text: "Live phishing feed (OpenPhish, downloaded " + String(feed.downloaded_at || "").slice(0, 10) + "): " + feed.detected + " of " +
              feed.urls_on_domains_not_in_training + " links on domains never seen in training were flagged (" + pct(feed.recall) + ")." })),
      h("h3", { text: "Price of being explainable" }),
      h("p", { class: "small", text: "A gradient-boosting model (not explainable) on the same features, both at threshold 0.5:" }),
      simpleTable(["Test set", "Black box accuracy", "Scorecard accuracy", "Black box AUC", "Scorecard AUC"], bbRows),
      h("details", {}, h("summary", { text: "Full scorecard (" + U.scorecard.length + " rows)" }),
        simpleTable(["Feature", "From", "To", "Points", "Training URLs"],
          U.scorecard.map((r) => [r.feature, r.from, r.to === null ? "and above" : r.to, (r.points > 0 ? "+" : "") + r.points.toFixed(2), fmtInt(r.train_rows)])))));

    // SHAP: global feature importance
    if (card.shap) {
      const Sh = card.shap;
      const imp = (title, part, nameOf) => {
        const items = part.top_features.slice(0, 12);
        const max = Math.max(...items.map((i) => i.mean_abs_shap), 1e-9);
        return h("div", {}, h("h3", { text: title }),
          h("p", { class: "small muted", text: "Base value " + part.base_log_odds.toFixed(2) + " (" + pct(part.base_probability, 1) +
            ") from " + fmtInt(part.background_rows) + " training examples; importance over " + fmtInt(part.test_rows) + " test examples." }),
          h("div", { class: "barlist" }, items.map((i) => {
            const bar = h("div", { class: "bar" + (i.pushes === "safe" ? " lvl-Safe" : i.pushes === "scam" ? " lvl-Critical" : "") });
            bar.style.width = (100 * i.mean_abs_shap / max) + "%";
            return h("div", { class: "row" }, h("div", { class: "name", text: nameOf(i) }),
              h("div", { class: "val", text: i.mean_abs_shap.toFixed(3) }), h("div", { class: "track" }, bar));
          })));
      };
      nodes.push(h("div", { class: "card" }, h("h2", { text: "Explainability with SHAP" }),
        h("p", { text: "Every model decision is explained with SHAP (SHapley Additive exPlanations). Our models are linear, so the SHAP values are exact: " +
          "SHAP of a feature = weight × (its value − its average in the training data). The base value plus all SHAP values equals the model output, " +
          "and our values are checked against the official shap library (LinearExplainer) in the automated tests." }),
        h("p", { class: "small muted", text: "Below: global importance, the average absolute SHAP value of each feature over the held-out test data. " +
          "Red = pushes towards scam, green = towards safe. Each result page shows a SHAP waterfall for that message." }),
        h("div", { class: "two-col" },
          imp("SMS / chat text model", Sh.text.sms, (i) => tokenName(i.feature)),
          imp("E-mail text model", Sh.text.email, (i) => tokenName(i.feature))),
        imp("URL model (per link feature)", Sh.url, (i) => i.label)));
    }

    // Datasets
    const dsName = { sms_spam: "SMS Spam Collection (UCI)", phishing_email: "Phishing Email Dataset (Hugging Face)",
      phiusiil: "PhiUSIIL Phishing URL (UCI)", web_page_phishing: "Web page phishing URLs (Hugging Face)" };
    nodes.push(h("div", { class: "card" }, h("h2", { text: "Data" }),
      h("p", { class: "small muted", text: "Public datasets, downloaded by ml/download_data.py. Checksums are stored in data/raw/manifest.json." }),
      simpleTable(["Dataset", "Rows downloaded", "Rows used", "Safe", "Scam"],
        Object.entries(M.datasets).map(([k, d]) => [dsName[k] || k, fmtInt(d.rows_raw), fmtInt(d.rows_used), fmtInt(d.class_balance_used.safe), fmtInt(d.class_balance_used.scam)])),
      Object.entries(M.datasets).map(([k, d]) => h("details", {}, h("summary", { text: "Notes: " + (dsName[k] || k) }),
        h("ul", { class: "limits" }, d.notes.map((n) => h("li", { text: n })))))));

    // Rules
    nodes.push(h("div", { class: "card" }, h("h2", { text: "Language rules" }),
      h("p", { class: "small muted", text: "Hand-written patterns. Weights are set by hand, not learned. " + card.brands + " organisations are on the impersonation list." }),
      simpleTable(["Rule group", "Weight", "English", "Hinglish", "Hindi"],
        card.rules.map((g) => [g.title, g.weight + " to " + g.max_weight, g.patterns.en, g.patterns.hinglish, g.patterns.hi]))));

    // Limits
    nodes.push(h("div", { class: "card" }, h("h2", { text: "Known limits" }),
      h("ul", { class: "limits" },
        h("li", { text: "The text models were trained on English only: SMS from the UK and Singapore (2006-2012) and older e-mail corpora. Hindi and Hinglish are covered by rules, not by a model." }),
        h("li", { text: "No labelled Indian scam dataset was found. India-specific scams (KYC, electricity bill, digital arrest, UPI) are detected by hand-written rules, and their accuracy has not been measured." }),
        h("li", { text: "The text models read routine Indian bank alerts and shop messages as spam. They are therefore not used for OTP / transaction alerts or when every link goes to an official domain." }),
        h("li", { text: "The URL model reads only the text of a link. It does not open the page, so a clean-looking link to a harmful page is missed." }),
        h("li", { text: "The organisation list is a hand-made starter list. An organisation that is not on it cannot be flagged for impersonation." }),
        h("li", { text: "There is no login. Analyst accounts and roles are future work." }))));

    nodes.push(h("p", { class: "small muted", text: "Metrics generated " + M.generated_at + " with scikit-learn " + M.versions.scikit_learn + ", Python " + M.versions.python + ", seed " + M.seed + "." }));
    host.replaceChildren(...nodes);
  }

  async function loadAbout() {
    if (aboutLoaded) return;
    try { renderAbout(await api("/api/model-card")); aboutLoaded = true; }
    catch (err) { toast(err.message); }
  }

  // ---------- assistant ----------

  const chatState = { history: [], greeted: false, busy: false };
  const SOURCE_NOTE = { result: "From your scan result", faq: "From the built-in safety guide", fallback: "Built-in assistant" };

  /** Plain-text answer to nodes: '- ' lines become a list, **bold** and `code` are styled. Text only, never HTML. */
  function richText(text) {
    const box = h("div", {});
    let list = null;
    const code = (s) => s.split(/`([^`]+)`/g).map((part, i) => (i % 2 ? h("code", { text: part }) : part));
    const inline = (s) => s.split(/\*\*(.+?)\*\*/g).map((part, i) => (i % 2 ? h("b", {}, code(part)) : code(part)));
    for (const raw of String(text).split("\n")) {
      const line = raw.trim();
      if (!line) { list = null; continue; }
      const m = /^[-*•]\s+(.*)$/.exec(line);
      if (m) {
        if (!list) { list = h("ul", {}); box.append(list); }
        list.append(h("li", {}, inline(m[1])));
      } else { list = null; box.append(h("p", {}, inline(line))); }
    }
    return box;
  }

  function chatBubble(role, content, src) {
    const row = h("div", { class: "msg-row " + role },
      h("div", { class: "bubble" }, role === "bot" ? richText(content) : h("p", { text: content })),
      src ? h("div", { class: "msg-src", text: src }) : null);
    const log = $("#chat-log");
    log.append(row);
    // Show the start of a long answer, not its end.
    log.scrollTop = role === "bot" ? Math.max(0, row.offsetTop - log.offsetTop - 8) : log.scrollHeight;
    return row;
  }

  function refreshChatSuggestions() {
    const host = $("#chat-suggest");
    if (!host || !META) return;
    const chips = [];
    const chip = (label, onclick) => h("button", { type: "button", class: "chip", onclick: onclick, text: label });
    if (lastScan) {
      chips.push(chip("Why is this rated " + lastScan.level + "?", () => sendChat("Why is this rated " + lastScan.level + "?")));
      chips.push(chip("Is it safe to click the link?", () => sendChat("Is it safe to click the link?")));
      chips.push(chip("What should I do now?", () => sendChat("What should I do now?")));
    }
    const pick = ["lost-money", "digital-arrest", "report", "upi", "kyc", "check-link"];
    for (const id of pick) {
      const q = META.assistant.questions.find((x) => x.id === id);
      if (q) chips.push(chip(q.q, () => sendChat(q.q, q.id)));
    }
    host.replaceChildren(...chips);
  }

  async function sendChat(message, faqId) {
    message = (message || "").trim();
    if (!message || chatState.busy) return;
    chatState.busy = true;
    chatBubble("user", message);
    const typing = h("div", { class: "msg-row bot" }, h("div", { class: "bubble typing", "aria-label": "Assistant is typing" }, h("i"), h("i"), h("i")));
    $("#chat-log").append(typing);
    $("#chat-log").scrollTop = $("#chat-log").scrollHeight;
    const body = { message: message, history: chatState.history.slice(-8) };
    if (lastScan) body.context = { text: lastScan.text, channel: lastScan.channel, sender: lastScan.sender };
    if (faqId) body.faq_id = faqId;
    try {
      const [r] = await Promise.all([
        api("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
        sleep(450)]);
      typing.remove();
      const src = r.source === "ai" ? "AI answer · Groq (" + r.model + ")" : SOURCE_NOTE[r.source] || "";
      chatBubble("bot", r.answer, src + (r.note ? " · " + r.note : ""));
      chatState.history.push({ role: "user", content: message.slice(0, 2000) }, { role: "assistant", content: r.answer.slice(0, 2000) });
    } catch (err) {
      typing.remove();
      chatBubble("bot", "Sorry, I could not answer that: " + err.message);
    } finally {
      chatState.busy = false;
    }
  }

  function openChat(question) {
    const panel = $("#chat-panel");
    panel.hidden = false;
    $("#chat-fab").hidden = true;
    $("#chat-fab").setAttribute("aria-expanded", "true");
    if (!chatState.greeted) {
      chatState.greeted = true;
      chatBubble("bot", "Namaste! Ask me about your result or any scam.");
    }
    refreshChatSuggestions();
    if (question) sendChat(question); else $("#chat-input").focus();
  }

  function initChat() {
    const ai = META.assistant && META.assistant.ai;
    $("#chat-mode").textContent = ai ? "AI mode · Groq" : "Offline mode";
    $("#chat-foot").textContent = ai
      ? "AI answers can be wrong. Groq gets your question and a scan summary, never the message."
      : "Offline answers from your result and a safety guide.";
    $("#chat-fab").addEventListener("click", () => openChat());
    $("#chat-close").addEventListener("click", () => {
      $("#chat-panel").hidden = true;
      $("#chat-fab").hidden = false;
      $("#chat-fab").setAttribute("aria-expanded", "false");
      $("#chat-fab").focus();
    });
    $("#chat-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      const input = $("#chat-input");
      const q = input.value;
      input.value = "";
      sendChat(q);
    });
  }

  // ---------- live alerts (messages checked automatically) ----------

  const SOURCE_NAME = { "sms-app": "📱 SMS on phone", "email-watch": "📧 New e-mail", "gmail-web": "📧 Gmail" };
  let alertSeq = null;

  function showAlert(a) {
    const host = $("#alert-stack");
    const close = h("button", { type: "button", class: "icon-btn", "aria-label": "Dismiss", text: "✕" });
    const card = h("div", { class: "alert-card lvl-border-" + a.level, role: "alert" },
      h("div", { class: "alert-top" },
        h("span", { class: "alert-src", text: SOURCE_NAME[a.source] || a.source }), close),
      h("div", { class: "alert-main" }, levelBadge(a.level), h("b", { text: String(a.score) }),
        a.category && a.category !== "None" ? h("span", { class: "muted small", text: a.category }) : null),
      a.sender ? h("div", { class: "small muted", text: "From " + a.sender }) : null,
      h("div", { class: "alert-snippet", text: a.snippet }),
      h("button", { type: "button", class: "btn small primary", onclick: () => { card.remove(); openCase(a.case_id); } }, "Open case"));
    close.addEventListener("click", () => card.remove());
    host.prepend(card);
    while (host.children.length > 3) host.lastChild.remove();
    setTimeout(() => card.remove(), 30000);
    if (window.Notification && Notification.permission === "granted" && document.hidden) {
      try { new Notification("SatarkAI: " + a.level + " risk", { body: (SOURCE_NAME[a.source] || "") + "\n" + a.snippet, icon: "/static/favicon.svg" }); }
      catch (e) { /* ignore */ }
    }
  }

  async function pollAlerts() {
    try {
      const r = await api("/api/alerts?after=" + (alertSeq || 0));
      if (alertSeq !== null) r.alerts.forEach(showAlert);   // the first poll only learns where the feed is
      alertSeq = r.latest;
      if (r.alerts.length && alertSeq !== null && !$("#view-dashboard").hidden) loadDashboard();
    } catch (e) { /* server restarting: try again next time */ }
    setTimeout(pollAlerts, 3000);
  }

  // ---------- routing, theme, start-up ----------

  const VIEWS = ["analyze", "history", "dashboard", "about"];

  function route() {
    const raw = (location.hash || "#analyze").slice(1);
    const caseMatch = /^case\/(\d+)$/.exec(raw);
    const view = caseMatch ? "history" : (VIEWS.includes(raw) ? raw : "analyze");
    for (const v of VIEWS) $("#view-" + v).hidden = v !== view;
    for (const a of $$(".tabs a")) {
      if (a.dataset.view === view) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    }
    if (view === "history") loadHistory();
    if (view === "dashboard") loadDashboard();
    if (view === "about") loadAbout();
    if (caseMatch) openCase(Number(caseMatch[1]));
  }

  function initTheme() {
    $("#theme-toggle").addEventListener("click", () => {
      const root = document.documentElement;
      const dark = root.getAttribute("data-theme")
        ? root.getAttribute("data-theme") === "dark"
        : window.matchMedia("(prefers-color-scheme: dark)").matches;
      const next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("satark-theme", next); } catch (e) { /* ignore */ }
      if (lastStats && !$("#view-dashboard").hidden) renderDashboard(lastStats);  // charts read colours from CSS
    });
  }

  async function start() {
    initTheme();
    try { META = await api("/api/meta"); }
    catch (err) { toast("Cannot reach the server: " + err.message); return; }
    $("#app-name").textContent = META.app;
    $("#foot-text").textContent = META.app + " " + META.version;
    document.title = META.app + " - " + META.tagline;
    initAnalyze();
    initHistory();
    initChat();
    pollAlerts();
    if (window.Notification && Notification.permission === "default") {
      document.addEventListener("click", () => { try { Notification.requestPermission(); } catch (e) { /* ignore */ } }, { once: true });
    }
    for (const r of $$("input[name=range]")) r.addEventListener("change", loadDashboard);
    $("#case-close").addEventListener("click", () => $("#case-dialog").close());
    $("#case-dialog").addEventListener("click", (ev) => { if (ev.target === ev.currentTarget) ev.currentTarget.close(); });
    window.addEventListener("hashchange", route);
    route();
  }

  document.addEventListener("DOMContentLoaded", start);
})();
