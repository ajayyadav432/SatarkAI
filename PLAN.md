# SatarkAI — Hackathon Plan

IEEE-IGNITE Hackathon, 14–15 Oct 2026
Problem statement: **SKIT025 — AI-Based Phishing, Scam Message and Malicious URL Detection**

> "SatarkAI" (satark = alert) is only a working name. It is set in one place
> (`app/config.py`), so you can rename it in a few seconds.

---

## 1. Why this problem statement

The PDF has 25 problem statements. Our setup is a laptop with no sensors, no boards
and no GPU, and we want something that runs on localhost with test cases. That removes
most IoT / EV / robotics statements and SKIT022 (AutoCAD only).

| Rank | PS | Why | Main risk |
|---|---|---|---|
| **1 (chosen)** | SKIT025 Phishing / scam / malicious URL | Every expected point can be built in software and run offline. Real public datasets exist, so accuracy is measured, not claimed. Judges can paste their own SMS or link. | Popular, so it must be polished |
| 2 | SKIT021 Student participation platform | Safest to finish completely | Little AI, crowded |
| 3 | SKIT003 Gambling / Ponzi website detection | Suits explainable rules | No labelled dataset found, needs internet in the demo |
| 4 | SKIT010 DG placement and sizing | Checkable against published IEEE 33-bus results | Needs power-system knowledge to defend |

## 2. What we are building

A web app where a user or security analyst pastes an SMS, email, social-media message
or URL and gets:

1. a **risk level** (Safe / Low / Medium / High / Critical) with a 0–100 score,
2. the **reasons** for that level, in plain language, with the suspicious words highlighted,
3. every **URL, domain, phone number, UPI ID and email** found in the message,
4. a **warning page** before a risky link is opened,
5. a **searchable history** of all analysed cases, and
6. a **dashboard** for security analysis.

It works fully offline. No paid API and no API key is needed.

## 3. PS requirement → what we build

The left column is copied word for word from the PDF.

| # | Expected solution should | What we build | Code |
|---|---|---|---|
| R1 | Analyze message text and URLs. | One analysis pipeline for text + every URL inside it | `app/analysis/pipeline.py` |
| R2 | Identify suspicious linguistic patterns. | 19 rule groups (urgency, threats, rewards, credential requests, ...) in English, Hinglish and Hindi + two ML text models | `rules.py`, `models.py` |
| R3 | Extract and analyze URLs, domains and relevant metadata. | URL extraction (also `hxxp`, `[.]`, bare domains), registered domain, TLD, subdomains, IP host, punycode, shorteners, entropy, lookalike check. Optional live DNS / domain-age lookup | `extract.py`, `url_features.py` |
| R4 | Detect impersonation and urgency-based scam patterns. | Brand list with official domains; flags a brand name used with a non-official domain, typosquats (`paypa1`), sender mismatch, urgency rules | `brands.py`, `rules.py` |
| R5 | Classify messages according to risk level. | 0–100 score → 5 levels, plus a scam category (KYC, lottery, courier, job, ...) | `scoring.py` |
| R6 | Explain the factors contributing to the risk classification. | Every factor is listed with its weight and the exact evidence text. ML models are linear, so their word / feature contributions are exact, not guessed | `scoring.py`, UI |
| R7 | Provide warnings before users interact with suspicious content. | Links are shown defanged and not clickable. Opening goes through a warning page (`/go`). Browser extension that warns before a link click | `static/go.html`, `extension/` |
| R8 | Maintain a searchable history of analyzed cases. | SQLite with full-text search, filters, pagination, analyst status and notes, CSV export | `app/db.py` |
| R9 | Provide a dashboard for security analysis. | KPIs and charts: risk levels, trend over time, scam categories, top indicators, impersonated brands, top domains | `static/` |

## 4. Architecture

```
Browser (plain HTML + JS, no build step)        Browser extension (stretch)
        |                                               |
        +-------------------- HTTP ---------------------+
                              |
                    FastAPI  (one process, port 8000)
                              |
     +------------+-----------+-----------+--------------+
     |            |                       |              |
  extract     rule engine            ML models        SQLite
  URLs and    (patterns,          text: TF-IDF + LR   history +
  entities    brands, URL         (SMS and e-mail)    full-text
              heuristics)         URL: scorecard LR   search
                              |
                    scoring: combine evidence
                    -> score, level, category, reasons
```

Stack: Python 3.13, FastAPI, scikit-learn, SQLite (FTS5), plain HTML/CSS/JS, Chart.js
stored locally (no CDN, so it works without internet).

## 5. How the risk score works

Every piece of evidence has a weight between 0 and 1. Evidence is combined as

```
risk = 1 − (1 − w1) × (1 − w2) × (1 − w3) × ...
```

So one weak signal gives a low score, several signals add up, and the score can never
pass 100. Each factor is shown to the user with its own weight and the text that
triggered it.

- Rule and link-check weights are set by hand. They are not learned.
- A model's weight grows with its probability. Text model: 0.15 at probability 0.5 up to
  0.45 at 1.0. URL model: 0.25 at its alert threshold (0.84) up to 0.55 at 1.0.
- **High and Critical need at least one strong indicator (weight 0.30 or more) that is
  not a model.** Without one the score stops at 59 (Medium), and the user is told.
- If the text is in a language the model was not trained on, the text model is
  **skipped and the user is told so**, instead of producing a made-up probability.
  Rule: fewer than 60% of the message's words are known to the model.
- The text model is also skipped for routine OTP / transaction alerts and for messages
  whose only links go to official domains (reason in section 12, finding 3).
- A link to a known official domain is not treated as suspicious.
- The same trick in several links counts once.

Levels: Safe 0–19 · Low 20–39 · Medium 40–59 · High 60–79 · Critical 80–100.

## 6. Data and models

All sources below were downloaded on this machine on 14 Oct 2026: public, no login.
Row counts, class balance and checksums are in section 12 and in `models/metrics.json`.
Nothing here is quoted from memory.

| Dataset | Used for | Source | Licence shown by host |
|---|---|---|---|
| SMS Spam Collection | text model (SMS) | UCI ML Repository, dataset 228 | CC BY 4.0 |
| Phishing Email Dataset | text model (email) | Hugging Face `zefang-liu/phishing-email-dataset` | LGPL-3.0 |
| PhiUSIIL Phishing URL | URL model (domain features) | UCI ML Repository, dataset 967 | CC BY 4.0 |
| Web page phishing URLs | URL model (subdomain and path features) | Hugging Face `pirocheto/phishing-url` | CC BY 4.0 |
| OpenPhish community feed | **testing only**, never training | GitHub `openphish/public_feed` | non-commercial use only |

Models (chosen because they can be explained exactly):

- **Text models**: TF-IDF word n-grams + Logistic Regression. One model for SMS / chat
  and one for e-mail, because a model trained on one fails on the other (section 12).
- **URL model**: 27 features computed from the URL string only (length, digits, hyphens,
  subdomains, entropy, TLD, ...), binned, then Logistic Regression — a scorecard.
  We also train a gradient-boosting model only to report how much accuracy the
  explainable model gives up.

Honesty rules for this project:

1. Every metric shown in the app is read from `models/metrics.json`, which the training
   script writes. No number is typed by hand.
2. Metrics are computed on a held-out test split that is never used for training or tuning.
3. India-specific scam patterns (KYC, electricity bill, "digital arrest", UPI) come from
   **hand-written rules**, not from the ML model, because no labelled Indian dataset was
   found. The app says this clearly.
4. Demo cases added to fill the dashboard are tagged `demo-seed` and shown with a badge.

## 7. Folder layout

```
app/            FastAPI app (main.py, db.py, config.py)
  analysis/     extract, url_features, url_scorecard, brands, rules, textprep,
                models, scoring, pipeline, lookup
  data/         brands.json, patterns.json, url_lists.json, samples.json (editable knowledge)
  static/       index.html, app.js, styles.css, go.html, go.js, vendor/
ml/             download_data.py, train.py (training and evaluation), sanity_legit_urls.txt
models/         trained models + metrics.json
data/raw/       downloaded datasets (one folder each) + manifest.json
tests/          unit, API, security, model, acceptance (R1–R9), e2e
extension/      browser extension
scripts/        seed_demo.py, check_brands.py
run.sh          one command to start, test, train, seed
```

## 8. Build steps

- [x] 1. Project skeleton, virtual environment, pinned dependencies
- [x] 2. Download datasets, record size / licence / checksum, inspect for bias
- [x] 3. Extraction: URLs, domains, phones, UPI IDs, emails, amounts
- [x] 4. URL features and heuristics, brand and typosquat detection
- [x] 5. Rule engine for linguistic patterns
- [x] 6. Train and evaluate text and URL models, write `metrics.json`
- [x] 7. Scoring and full pipeline
- [x] 8. SQLite history with full-text search
- [x] 9. REST API
- [x] 10. Web UI: Analyze, History, Dashboard, Model card, warning page
- [x] 11. Run on localhost, run all tests, fix what fails
- [x] 12. Stretch: bulk CSV upload, browser extension, live domain lookup
- [x] 13. README and demo script

## 9. Test plan

| Group | What is tested | How |
|---|---|---|
| Acceptance R1–R9 | One test per PS requirement, end to end through the API | pytest |
| Extraction | URLs (plain, defanged, bare domain, punycode), phones, UPI, emails | pytest |
| URL analysis | IP host, shortener, lookalike, subdomain tricks, official domains not flagged | pytest |
| Rules | Each pattern group fires on a scam example and stays silent on a normal one | pytest |
| Scoring | Levels at boundaries, more evidence never lowers the score | pytest |
| History | Save, search, filters, pagination, status update, delete, CSV export | pytest |
| API | Valid input, empty, too long, wrong types, unknown id | pytest |
| Security of our own app | Script injection in messages, SQL injection in search, CSV formula injection, blocked internal addresses in live lookup | pytest |
| Models | Models load, held-out metrics above a floor, sanity sets (real brands must not be High) | pytest |
| UI end to end | Analyse → see reasons → history → dashboard → warning page | headless Chromium (Playwright) |

Result on 14 Oct 2026: **302 tests, all pass** (`./run.sh test`, about 75 seconds).
218 are unit / API / security / model / acceptance tests and 9 run in a real headless
browser. The browser tests are skipped automatically if Playwright is not installed.

## 10. How to run

```bash
./run.sh            # creates the environment if needed, starts http://localhost:8000
./run.sh test       # runs all tests
./run.sh train      # downloads data and retrains the models
./run.sh seed       # adds demo cases (tagged demo-seed); ./run.sh unseed removes them
```

## 11. Known limits (say these to judges before they ask)

- Text training data is English and mostly from the UK, Singapore and the US. Hindi and
  Hinglish are covered by rules only.
- The accuracy of the India-specific rules is **not measured**: there is no labelled
  Indian dataset. The example messages in the app were written by us and were also used
  to tune the rules, so they prove the feature works, not how accurate it is.
- The URL model reads the URL string only. It does not open the page.
- The brand list is a hand-made starter list. A brand that is not in it cannot be
  flagged for impersonation.
- No login screen. Analyst accounts and roles are future work.

## 12. Progress and findings log

Status on 14 Oct 2026: **all 13 build steps are done.** The app runs on
http://localhost:8000 and 302 tests pass. Every number below is copied from
`models/metrics.json` (generated 2026-10-14 07:12, scikit-learn 1.9.1, seed 42) or from
a test run on this machine.

### Data as downloaded (checksums in `data/raw/manifest.json`)

| Dataset | Rows downloaded | Rows used | Safe / scam used | What was removed |
|---|---|---|---|---|
| SMS Spam Collection | 5,574 | 5,159 | 4,517 / 642 | 415 duplicates |
| Phishing Email Dataset | 18,650 | 17,478 | 10,973 / 6,505 | 16 with no text, 533 whose text is the word "empty", 16 shorter than 20 characters, 607 duplicates |
| PhiUSIIL Phishing URL | 235,795 | 197,603 domains | 132,080 / 65,523 | reduced to registered domains: 37,585 repeats, 106 domains that appear in both classes |
| Web page phishing URLs | 11,430 | 11,429 | 5,715 / 5,714 | 1 duplicate |

### Results on held-out test data

| Model | Test items | Accuracy | Precision | Recall | False alarms | ROC AUC |
|---|---|---|---|---|---|---|
| Text, SMS / chat | 1,032 | 98.55% | 97.48% | 90.62% | 0.33% | 0.997 |
| Text, e-mail | 3,496 | 98.26% | 98.36% | 96.93% | 0.96% | 0.999 |
| URL scorecard, all | 41,543 | 81.29% | 96.58% | 45.92% | 0.82% | 0.842 |
| URL scorecard, full URLs only | 2,021 | 74.67% | 95.43% | 51.73% | 2.47% | 0.884 |

Always answering the majority class would score 87.6% (SMS), 62.8% (e-mail) and 66.4%
(URLs). Splits: text 80/20 stratified after removing duplicates; URLs 80/20 by
registered domain, so no domain is in both parts.

### Findings (each one changed the design)

1. **PhiUSIIL gives the label away.** 100% of its legitimate URLs are `https`, start with
   `www` and have no path or query; only 2.8% have any other subdomain. Phishing URLs:
   48.7% `https`, 41.4% `www`, 27.2% with a path. A model can score about 99% by learning
   this, and would then flag every real link that has a path. Fix: only the registered
   domain is taken from PhiUSIIL; scheme and `www` are never features; subdomain and path
   features are learned from the other URL dataset, where legitimate URLs do have paths.
   A test checks that `http`, `https` and `www` do not change the score.
2. **Text models do not transfer between channels.** The SMS model on e-mail: 59.0%
   accuracy, 33.7% false alarms. The e-mail model on SMS: 54.2% accuracy, 49.3% false
   alarms. A single combined model lowered SMS precision to 89%. So there are two models,
   chosen by message type.
3. **The text model misreads normal Indian bank messages.** An early combined model gave
   a genuine OTP message 77% and a genuine debit alert 91% scam probability. The final
   SMS model still gives the OTP message 68% (the debit alert is skipped by the
   vocabulary check: only 38% of its words are known). Reason: the training data (UK
   personal chat against UK advertising spam) has no bank alerts. Fix: the text model is
   not used for routine OTP / transaction alerts, or when every link goes to an official
   domain, unless something else is suspicious. The app says so each time.
4. **Sloppy typing looks like links.** On the 4,827 normal SMS, "Wife.how", "her.love",
   "days.so" matched real domain endings: 51 messages had a false link. A bare
   `name.tld` with no `http`, `www` or path is now a link only for endings that are not
   everyday words. After the fix: 14 messages, all with real domains.
5. **Weak signals plus a model produced High.** "Call 98765... for the notes, urgent"
   was rated High. Now High and Critical need one strong non-model indicator; otherwise
   the score stops at 59.
6. **A lower alert threshold for the URL model means too many false alarms.** At 0.5 it
   flags 16.3% of legitimate full URLs. The threshold 0.84 was chosen on validation data
   (not test data) to keep that at or below 5%; on test data it is 2.5%. Recall drops to
   45.9%, which the link checks and wording rules cover.
7. **Being explainable costs little.** A gradient-boosting model on the same features
   reaches 83.9% accuracy at threshold 0.5, the scorecard 83.1% (AUC 0.862 against 0.842).
8. The e-mail corpus contains words that only identify its source (one company's staff,
   one mailing list). 20 such words are removed from the vocabulary (`textprep.py`).
   Topic bias remains and is listed under known limits.
9. `onlinesbi.com` did not resolve in DNS, so it was taken off the official list.
   Content platforms (`docs.google.com`, `github.io`, `t.me`, ...) are never "official",
   even when the company owns the domain, because anyone can publish there.

### Extra checks

- **Live phishing feed (OpenPhish, downloaded 14 Oct 2026):** 300 URLs, 296 on domains
  not seen in training, **233 flagged (78.7%)**. Phishing only, so this measures recall.
- **80 well-known legitimate links typed by hand:** 1 wrongly flagged
  (`https://huggingface.co/datasets`, because of the `.co` ending).
- **Hand-written demo messages:** all 32 scam examples score 67 or more (High or
  Critical) and all 12 genuine examples score 12 or less (Safe). These examples were
  also used to tune the rules, so this is not an accuracy measurement.
- **Live domain lookup, tried for real:** `wikipedia.org` → registered 2001-01-13;
  a non-existent `.xyz` → "does not exist in DNS"; `192.168.1.1` → blocked as internal.
- **Browser extension, tested in headless Chromium:** risky link → warning page;
  harmless link → opens normally; same-site link → not checked; app not running →
  nothing is blocked.

### Problems found by the tests and fixed

- A harmless "call this number, urgent" message was rated High (finding 5).
- A "bank" e-mail from a Gmail address was not flagged, because `gmail.com` is on
  Google's official list. Free-mail domains are now never treated as official senders.
- "call SBI customer care 98765..." was not seen as a call-back request.
- Hindi "अपना ओटीपी किसी को न बताएं" (do not share your OTP) was read as a request.
- "Extracted indicators" showed `[object HTMLElement]`; several phone-width layouts
  scrolled sideways. Found in screenshots and by the browser test.

### Not done / open

- Accuracy on real Indian scam messages is unknown (no labelled data).
- No login or analyst roles.
- The extension was tested in headless Chromium only, not in a normal Chrome window.
- Tested with Python 3.13 only.
