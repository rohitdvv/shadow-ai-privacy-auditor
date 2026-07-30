# Shadow AI Privacy Auditor

**Check what you are about to paste into ChatGPT, Gemini or Copilot — before you paste it.**

### ▶︎ [Try the live web app](https://rohitdvv.github.io/shadow-ai-privacy-auditor/) · [Download the extension](https://github.com/rohitdvv/shadow-ai-privacy-auditor/releases/latest)

A local-only privacy auditor that finds sensitive information in text, explains why each item is risky, and produces a redacted version that is still useful to send. It ships as two things that share one detection engine:

| | What it is | Where it runs |
| --- | --- | --- |
| **Web app** | Paste text, review findings, copy the safe version | Any static host — `index.html` |
| **Chrome extension** | Watches the composer on AI chat sites and interrupts risky sends | Manifest V3, `extension/` |

> **Nothing you type ever leaves your device.** There is no backend, no API key and no analytics. `npm run verify:offline` fails the build if any shipped file contains `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, a remote import or a remote asset reference. The web app additionally ships a `connect-src 'none'` Content-Security-Policy, so the browser itself blocks outbound requests.

---

## Quick start

```bash
git clone https://github.com/rohitdvv/shadow-ai-privacy-auditor
cd shadow-ai-privacy-auditor

npm run serve        # → http://localhost:4173
npm test             # 36 fictional cases + 45 benign prompts
npm run verify:offline
npm run build        # regenerates the extension bundle + docs/TEST_RESULTS.md
```

No dependencies. No build step for the web app — it is native ES modules and static files. Node 18+ is only needed for the tests and the extension bundler.

### Installing the extension

1. `npm run build:extension`
2. Open `chrome://extensions`, enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Open ChatGPT, Gemini, Claude, Copilot or Perplexity and start typing

> The live web app has a one-click **"Get the extension"** installer with the same steps.

---

## In the web app

- **Live risk gauge & verdict** — a 0–100 score with a plain-language "send / review / do not send" call, updated as you type.
- **Per-finding explanations** — every hit shows the category, severity, confidence, the line it's on, and *why it matters*, with keep/redact toggles.
- **Before ↔ After diff view** — see exactly which spans change, struck-through original beside each placeholder.
- **Four redaction styles** — numbered `[LABEL_1]`, plain `[LABEL]`, partial mask, or realistic pseudonyms.
- **Drag & drop / open file / paste from clipboard** — scan a `.txt`, `.md`, `.csv`, `.json`, `.env` or `.log` file entirely in-browser.
- **Quick sensitivity switch** — Relaxed / Balanced / Strict in one click, plus a full policy editor (categories, thresholds, custom terms, internal domains, custom regex rules).
- **Downloadable Markdown report** — findings metadata + the safe version (never the detected values).
- **Content-free activity log**, light/dark themes, full keyboard shortcuts (`?` for the list), and accessible, responsive layout.

---

## What it detects

All six categories from the brief are implemented.

| # | Category | Examples caught |
| --- | --- | --- |
| 1 | **Names & contact information** | full names (rule-based NER), emails, phone numbers, street addresses, postcodes, dates of birth, LinkedIn and social handles, IP and MAC addresses |
| 2 | **Government & financial identifiers** | SSN, ITIN, EIN, payment cards (Luhn + brand), IBAN (mod-97), ABA routing (checksum), bank accounts, SWIFT/BIC, passports, driver licences, Aadhaar (Verhoeff), PAN, UK NINO, Canadian SIN, crypto wallets |
| 3 | **Passwords, keys & credentials** | AWS/GitHub/Slack/Stripe/OpenAI/Anthropic/Google/SendGrid/Twilio/npm keys, JWTs, private-key blocks, DB connection strings, `Authorization:` headers, `.env` lines, inline password assignments, generic high-entropy secrets |
| 4 | **Medical & sensitive personal data** | MRNs, insurance member IDs, NPIs, ICD codes, 115 conditions, 102 medications, lab values, immigration status and USCIS A-numbers, protected attributes |
| 5 | **Employee, client & volunteer records** | employee/volunteer/client/case/donor IDs, salary and compensation, performance and disciplinary records, safeguarding case references, bulk people lists |
| 6 | **Confidential organisational information** | confidentiality markers, project codenames, internal system URLs and ticket keys, git remotes, unannounced financials and M&A, contract values, named client relationships |

Plus anything your organisation adds through **custom terms and custom regex rules** in the policy.

---

## The part that is hard: not over-redacting

A privacy tool that redacts everything gets switched off in a week. Precision is treated as a first-class requirement:

- **Safe-span protection.** Times, ISO and written dates, percentages, durations, version numbers, file sizes, figure/page references and existing `[PLACEHOLDER]` tokens are computed up front and excluded before any rule runs.
- **Checksum validation.** A 16-digit number is only a card if it passes Luhn *and* matches a real IIN range. An IBAN must pass mod-97. Aadhaar must pass Verhoeff. A routing number must pass the ABA weighted checksum.
- **Context requirements.** Nine rules refuse to fire without a nearby cue — a bare 9-digit number is only an SSN next to the words "SSN" or "social security".
- **A stop-list built for it.** The name recogniser rejects ~600 capitalised words that are not people: weekdays, months, job titles, product names, place names, document vocabulary, acronyms, and any run starting with a common noun (`Project Halberd` is a codename, not a person).
- **Prose-versus-secret discrimination.** `password is important` is prose; `password is Autumn!Ledger42` is a secret. The rule requires the captured value to look machine-set, not dictionary.
- **Educational framing is downgraded.** "What is type 2 diabetes?" scores 0. "Patient Marcus Chen was diagnosed with type 2 diabetes" scores 100.

**Measured result:** 45/45 ordinary prompts return zero findings, 0 false positives across the whole suite, and `The project meeting is scheduled for 3:00 PM.` comes back byte-for-byte unchanged.

---

## Results

```
cases      36/36 passed
benign     45/45 clean   (false-positive rate 0.0%)
precision  100.0%        (58 true positives, 0 false positives)
recall     100.0%        (0 missed)
F1         100.0%
speed      1.5 ms per prompt
```

Full case-by-case table, worked examples and redacted outputs: **[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md)**.

Reproduce with `npm test`. Every value in the corpus is fictional; identifier values were generated to satisfy their checksums so the validators are genuinely exercised.

---

## Worked example

**Input**

```text
Patient Marcus Chen (MRN 4482910) was diagnosed with type 2 diabetes and started on
metformin 500mg. Insurance member ID BCB8837421. NPI 1488736202.
```

**Risk score: 100/100 — Critical, do not send.** Six findings across two categories, each with a one-line explanation of the specific risk.

**Output**

```text
[NAME_1] (MRN [MEDICAL_RECORD_NUMBER_1]) was diagnosed with [MEDICAL_CONDITION_1] and started on
[MEDICATION_1] 500mg. Insurance member ID [INSURANCE_ID_1]. NPI [NPI_1].
```

Placeholders are consistent — the same person is always `[NAME_1]` — so the assistant can still follow the text. `500mg` and every other word are untouched.

---

## Tier 2 features

- **Chrome extension (MV3)** — real-time monitoring, send interception, one-click "redact and send" on 13 AI chat sites
- **Risk scoring** — 0–100 with five bands, dominated by the worst finding rather than by volume, with repeat-value decay
- **Severity levels** — critical / high / medium / low, with per-category policy overrides
- **Keep / redact controls** — per finding, in both the web app and the extension, plus redact-all and keep-all
- **One-click copy safe text** — and `Cmd/Ctrl + Enter`
- **Four redaction styles** — numbered, plain label, partial mask, realistic pseudonyms
- **Rule-based NER** — people and organisations, with signal-level explanations of why something was treated as a name
- **Configurable custom rules** — restricted terms, internal email domains, arbitrary regex, importable/exportable as JSON
- **Policy presets** — Balanced, Strict, Healthcare, Financial services, Engineering, Permissive
- **Content-free audit log** — counts and categories only, exportable as CSV, never the text
- **Accessibility** — keyboard navigable, skip link, ARIA labelling, reduced-motion support, light and dark themes

---

## How it works

```
text
 └─ safe-span pass          times, dates, versions, %, existing placeholders → protected
 └─ 72 pattern rules        regex + checksum/structural validators + context requirements
 └─ rule-based NER          capitalisation shape + given-name gazetteer + honorifics + role cues
 └─ context scorer          category cues raise confidence; placeholder/negation cues lower it
 └─ policy layer            category toggles, thresholds, severity overrides, custom rules
 └─ overlap resolution      severity → length → confidence
 └─ risk scoring            0-100 with worst-finding floor and repeat decay
 └─ redaction               span-exact replacement, stable placeholder identity
```

Full write-up, including every validator and the reasoning behind each design choice: **[docs/DETECTION.md](docs/DETECTION.md)**.

---

## Repository layout

```
index.html                 web app
assets/                    web app styles + controller
engine/                    the detection engine — shared by web app, extension and tests
  constants.js               categories, severities, risk bands
  validators.js              Luhn, IBAN mod-97, ABA, Verhoeff, NPI, entropy
  gazetteers.js              name / medical / business word lists
  patterns.js                72 pattern rules
  ner.js                     rule-based person & organisation recogniser
  context.js                 safe spans, context scoring, overlap resolution
  policy.js                  enterprise policy + custom-rule compilation
  risk.js                    0-100 scoring
  redact.js                  redaction + highlight segmentation
  engine.js                  scan orchestration
  audit.js                   content-free local log
extension/                 Manifest V3 Chrome extension
  content/                   real-time monitoring + send interception
  popup/  options/           status UI and full policy editor
  vendor/engine.bundle.js    generated — do not edit
tests/                     36 fictional cases, 45 benign prompts, runner with metrics
tools/                     bundler, icon generator, offline verifier, dev server
docs/                      detection write-up, results, limitations, demo script
```

---

## Responsible data use

- Every example in this repository is **fictional and invented for this project**. Names, organisations, addresses and domains are made up; domains use `.invalid`, `example.com` or fictional charities.
- Identifier values (cards, IBAN, Aadhaar, routing numbers) were **generated to satisfy their checksums** so the validators can be tested. They are not issued to anyone.
- Credential examples are vendor-published documentation values or random strings.
- **No real personal, medical, financial, immigration, employee, volunteer or organisational data is collected, stored or used anywhere in this project.**
- The tool does not transmit, store or log the text you scan. The optional activity log records counts and categories only, in your own browser, and can be cleared or disabled.
- The word lists in `gazetteers.js` are generic vocabulary (common given names, clinical nouns, business jargon) — no records, no scraped data.

---

## Known limitations

Summarised here, in full in **[docs/LIMITATIONS.md](docs/LIMITATIONS.md)**:

- English-first. Latin-script names are handled by shape, but the gazetteers, medical and business vocabulary are English.
- Rule-based NER cannot resolve genuine ambiguity — an unusual name with no supporting cue can be missed, and a capitalised product name can occasionally be treated as a person.
- Free-text confidential information without a marker word ("we are going to lose the Henderson account") is only partly detectable.
- Images, PDFs and other attachments are out of scope; only text is analysed.
- The extension's composer selectors track site DOMs that change without notice.
- Detection is a safety net, not a guarantee. It reduces accidental disclosure; it does not make a prompt safe by decree.

---

## Deployment

Static hosting, publish directory = repository root.

- **Vercel** — import the repo, accept the defaults (`vercel.json` included)
- **Netlify** — import the repo (`netlify.toml` included)
- **GitHub Pages** — enable Pages with "GitHub Actions"; `.github/workflows/deploy.yml` handles the rest

Live URL: _add after your first deploy_

---

## Licence

MIT — see [LICENSE](LICENSE).

Built for the **CDF Shadow AI Hackathon**.
