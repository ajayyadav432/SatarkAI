<p align="center"><img src="docs/logo.svg" alt="SatarkAI logo: a shield with a watchful eye" width="110"></p>

# SatarkAI

AI-based phishing, scam message and malicious URL detection.
IEEE-IGNITE Hackathon 2026, problem statement **SKIT025**.

Paste an SMS, e-mail, chat message or link. You get a risk level (Safe / Low / Medium /
High / Critical), the reasons for it, every link, phone number and UPI ID in the message,
a warning before any risky link opens, a searchable history and a security dashboard.

The analysis runs fully offline on one laptop. No API key, no paid service, no GPU. (The
assistant can optionally use Groq for free-form answers; see below.)

## Team

| Name | GitHub |
|---|---|
| Ajay Yadav | [@ajayyadav432](https://github.com/ajayyadav432) |
| Divyansh Shah | [@Divyanshshah01](https://github.com/Divyanshshah01) |
| manasvi15-git | [@manasvi15-git](https://github.com/manasvi15-git) |
| gauravpareek-web | [@gauravpareek-web](https://github.com/gauravpareek-web) |

## Run it

Use the terminal inside VS Code (the Python environment was created there).

```bash
./run.sh            # start the app, then open http://localhost:8000
./run.sh test       # run all 256 tests
./run.sh seed       # add demo cases so the dashboard is not empty
./run.sh unseed     # remove the demo cases
./run.sh demo       # demo web pages with fake scam links (fake social network) on http://127.0.0.1:8765
./run.sh phone      # keep the Android phone connected over USB (run in a second terminal)
./run.sh train      # download the datasets again and retrain the models (about 5 minutes)
```

On another computer, `./run.sh` rebuilds the Python environment by itself (needs internet
once). It was built and tested with Python 3.13 only. The trained models are already in
`models/`.

### AI assistant (optional)

The *Ask SatarkAI* assistant works without any setup: it answers from the scan result and
a built-in safety guide (`app/data/faq.json`). To let it answer free-form questions with
an AI model through Groq, copy `.env.example` to `.env` and put your key in it:

```bash
cp .env.example .env      # then edit .env:  GROQ_API_KEY=...
```

`.env` is in `.gitignore` and is never committed. Restart is not needed. Groq receives the
question and a summary of the scan (level, score, reasons, domains), never the full
message, because the message may contain instructions planted by the scammer.

## What to show in a 3-minute demo

1. **Analyze**: click the example *Bank KYC (SMS)*. The scan runs step by step, showing
   what each check found. Show the score, the highlighted words, and the list "Why this level" where every reason has a weight and the exact
   text that triggered it. The formula under the list reproduces the score.
2. Click *हिंदी KYC* and *Hinglish KYC*: same scam, three languages.
3. Click *Real OTP* and *Bank debit alert*: genuine messages stay Safe.
4. In the result, press **Open with caution** on the link: the warning page blocks the
   link until the user confirms, with a 5-second wait for High and Critical.
5. **History**: search `kyc`, `98765` or `sbi-kyc`. Open a case, set it to
   *Confirmed scam*, add a note. Export CSV.
6. **Dashboard**: cases per day, risk levels, scam categories, most common indicators,
   impersonated organisations, suspicious domains.
7. **How it works**: measured accuracy, the data, and the known limits.
8. **Ask SatarkAI** (bottom right): ask "Why is this rated Critical?" or
   "mera paisa gaya, kya karu?".

Tick *Instant result* next to Analyze to skip the step-by-step scan.

Paste your own messages too. That is the real test.

## How each requirement is met

| # | Problem statement (word for word) | Where |
|---|---|---|
| R1 | Analyze message text and URLs. | `app/analysis/pipeline.py` |
| R2 | Identify suspicious linguistic patterns. | `app/analysis/rules.py`, `app/data/patterns.json` (19 rule groups, 243 patterns: English, Hinglish, Hindi), text models |
| R3 | Extract and analyze URLs, domains and relevant metadata. | `extract.py`, `url_features.py`, optional live DNS / domain-age lookup in `lookup.py` |
| R4 | Detect impersonation and urgency-based scam patterns. | `brands.py` (39 organisations, lookalike spelling, brand name on a foreign domain, sender mismatch), urgency and threat rules |
| R5 | Classify messages according to risk level. | `scoring.py`: 0-100 score, 5 levels, scam category |
| R6 | Explain the factors contributing to the risk classification. | Every factor has a weight and its evidence. Both models are linear, so their word and feature contributions are exact |
| R7 | Provide warnings before users interact with suspicious content. | Links shown as `hxxp://bad[.]site`, warning page `/go`, browser extension in `extension/` |
| R8 | Maintain a searchable history of analyzed cases. | `app/db.py`: SQLite full-text search, filters, status, notes, CSV export, bulk upload |
| R9 | Provide a dashboard for security analysis. | Dashboard tab, `/api/stats` |

There is one automated test per requirement in `tests/test_acceptance.py`.

## Measured results

All numbers are written by `ml/train.py` into `models/metrics.json` and shown on the
*How it works* page. Test data was never used for training or tuning.

| Model | Test set | Accuracy | Precision | Recall | False alarms |
|---|---|---|---|---|---|
| Text, SMS and chat | 1,032 held-out SMS | 98.6% | 97.5% | 90.6% | 0.3% |
| Text, e-mail | 3,496 held-out e-mails | 98.3% | 98.4% | 96.9% | 1.0% |
| URL scorecard | 41,543 held-out URLs, domains never seen in training | 81.3% | 96.6% | 45.9% | 0.8% |

Extra checks of the URL model: 233 of 296 live OpenPhish links (downloaded 14 Oct 2026,
domains not in training) were flagged, which is 78.7%. Of 80 well-known legitimate links
typed by hand, 1 was wrongly flagged (`huggingface.co/datasets`).

**Why the URL number is not 99%.** In the PhiUSIIL dataset every legitimate URL is
`https://www.<domain>` with no path, and phishing URLs vary. A model can reach about 99%
there by learning "has `www` and no path", which is useless on real links. We removed
that shortcut: scheme and `www` are never features, and subdomain and path features are
learned only from a dataset where legitimate URLs do have paths. The honest number is
lower, and the model is tuned for few false alarms. Link checks and wording rules catch
what it misses.

## Known limits

- The text models are trained on English only (UK and Singapore SMS from 2006-2012, older
  e-mail corpora). Hindi and Hinglish are covered by rules, not by a model.
- No labelled Indian scam dataset was found. India-specific scams (KYC, electricity bill,
  digital arrest, UPI) are detected by hand-written rules. Their accuracy is not measured;
  the examples in the app were written by us and were also used to tune the rules.
- The text models read normal Indian bank alerts as spam, so they are switched off for
  OTP / transaction alerts and for messages whose only links go to official domains.
- The URL model reads only the text of a link. It does not open the page.
- The organisation list (`app/data/brands.json`) is a hand-made starter list. Check it
  before a real deployment: `python scripts/check_brands.py`.
- No login. Analyst accounts and roles are future work.

## Automatic checking (no copy-paste)

| Channel | How | Setup |
|---|---|---|
| SMS | Android app `android/` (SatarkAI SMS Guard) checks every incoming SMS and shows a notification | Build: `cd android && ./gradlew assembleDebug`. Phone and laptop on the same network; start the server with `SATARK_HOST=0.0.0.0 ./run.sh`; in the app enter `http://<laptop-ip>:8000` and the pairing code `SATARK_TOKEN` from `.env` |
| Websites | The extension checks every page as it loads (warning bar) and marks risky links (badge) | Load or reload `extension/` in `chrome://extensions` |
| Gmail in the browser | The extension shows a verdict bar above each opened e-mail | Same extension. Uses Gmail's page classes (`a3s`, `hP`, `gD`), which Gmail does not document |
| Inbox watcher | The server checks every new e-mail over IMAP, read-only | `IMAP_USER` and `IMAP_PASSWORD` (a Gmail app password) in `.env` |

The home page offers both downloads: the Android app (the latest build in `android/`) and the
extension as a zip (unzip, then `chrome://extensions` > Developer mode > Load unpacked). Click the
extension icon for an on/off switch and a list of the risky links on the current page.

Risky messages pop up as live alerts in the web app. With `SATARK_HOST=0.0.0.0`, other devices can only
call `/api/ingest`, and only with the pairing code; everything else stays on the laptop.

## Browser extension (optional)

`extension/` warns before a link on any web page opens.

1. Start the app (`./run.sh`).
2. In Chrome or Edge open `chrome://extensions`, switch on *Developer mode*, choose
   *Load unpacked* and select the `extension` folder.
3. Click a link to another site. Risky links open the SatarkAI warning page instead.

Links are sent only to `127.0.0.1` (this computer). If the app is not running, the
extension does not block anything.

## Project layout

```
app/
  main.py            REST API and static pages
  chat.py            the assistant: built-in answers, optional Groq
  db.py              history: SQLite + full-text search
  config.py          app name, limits, risk levels
  analysis/          extract, url_features, url_scorecard, brands, rules, textprep,
                     models, scoring, pipeline, lookup
  data/              brands.json, patterns.json, url_lists.json, samples.json, faq.json (editable)
  static/            index.html, app.js, styles.css, go.html, go.js, Chart.js and Inter font (local copies)
ml/                  download_data.py, train.py, sanity_legit_urls.txt
models/              trained models and metrics.json
tests/               256 tests: unit, API, security, models, acceptance R1-R9, browser
extension/           browser extension
scripts/             seed_demo.py, check_brands.py
PLAN.md              the plan, design decisions and the findings log
```

## Data sources

| Dataset | Used for | Licence shown by host |
|---|---|---|
| SMS Spam Collection, UCI ML Repository (228) | SMS text model | CC BY 4.0 |
| Phishing Email Dataset, Hugging Face `zefang-liu/phishing-email-dataset` | e-mail text model | LGPL-3.0 |
| PhiUSIIL Phishing URL Dataset, UCI ML Repository (967) | URL model, domain features | CC BY 4.0 |
| Web page phishing, Hugging Face `pirocheto/phishing-url` | URL model, subdomain and path features | CC BY 4.0 |
| OpenPhish community feed | extra test only, never training | non-commercial use only |

Chart.js 4.5.1 (MIT) is stored in `app/static/vendor/` so the dashboard works offline. The Inter
font (from @fontsource-variable/inter 5.2.8, SIL Open Font License, `app/static/vendor/fonts/OFL.txt`) is stored there too.
