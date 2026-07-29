# How detection works

A short technical write-up of the engine in `/engine`. Everything described here runs synchronously in the browser tab; there is no model server, no API call and no network dependency of any kind.

---

## 1. Why not just call an LLM?

An LLM would be the obvious way to find sensitive information. It is also the wrong tool for this specific job:

- **Sending the text to a model to check whether it is safe to send to a model** is circular. The prompt leaves the device either way.
- Detection would then depend on an API key, a network round trip and a per-scan cost, which rules out real-time monitoring as the user types.
- Results would be non-deterministic, so the same prompt could pass on Monday and fail on Tuesday, and there would be no way to write a regression test.

So the engine is fully deterministic and local. The trade-off is that it cannot reason about meaning, which is stated plainly in [LIMITATIONS.md](LIMITATIONS.md). Where meaning matters we compensate with context windows and gazetteers rather than pretending the problem does not exist.

---

## 2. The pipeline

```
input text
  │
  ├─ (a) safe-span pass          protect spans that must never be redacted
  ├─ (b) 72 pattern rules        regex → group extraction → context gate → validator
  ├─ (c) rule-based NER          people and organisations
  ├─ (d) context scoring         raise or lower confidence from surrounding words
  ├─ (e) policy layer            category filter, severity overrides, custom rules
  ├─ (f) thresholding            report ≥ reportThreshold, pre-tick ≥ redactThreshold
  ├─ (g) overlap resolution      severity → span length → confidence
  ├─ (h) risk scoring            0–100
  └─ (i) redaction               span-exact replacement with stable placeholders
```

### (a) Safe-span pass — `context.js`

Before anything else, the engine finds spans that are structurally safe and marks them off-limits:

| Protected | Example |
| --- | --- |
| clock times | `3:00 PM`, `15:30`, `9 am` |
| ISO and written dates | `2024-03-14`, `Tuesday, 14 March`, `Sept 3, 2025` |
| quantities and durations | `45 minutes`, `10 epochs`, `3.2%`, `six attendees` |
| version numbers | `v2.14.1`, `version 3` |
| file sizes and units | `512 MB`, `120 ms`, `1.8 kg` |
| document references | `Figure 4`, `page 12`, `Q3` |
| existing placeholders | `[NAME_1]`, `<EMAIL>`, `{{token}}`, `xxxx` |

A candidate finding that falls entirely inside a protected span is dropped. This is the single mechanism that guarantees the brief's canonical safe sentence — `The project meeting is scheduled for 3:00 PM.` — survives untouched.

Two rules opt out (`ignoreSafeSpans`), because their own regex already requires an explicit cue: date-of-birth (`DOB: 1988-04-17`) and clinical measurements (`A1C of 8.2%`). An ISO date is safe in general and sensitive when it is labelled as someone's birth date.

### (b) Pattern rules — `patterns.js`

72 rules across the six categories. A rule is a small declarative object:

```js
{
  id: 'payment_card',
  category: 'government_financial',
  severity: 'critical',
  label: 'CREDIT_CARD',                 // → [CREDIT_CARD_1]
  title: 'Payment card number',
  why: 'Card numbers are directly monetisable…',
  confidence: 0.95,
  regex: /\b(?:\d[ \-]?){12,18}\d\b/g,
  group: 0,                             // which capture group is the value
  needsContext: /…/i,                   // optional gate
  validate: (value, match, text) => …,  // boolean or { severity, confidence, note }
}
```

Three mechanisms keep precision high:

**Capture groups.** Many rules match a cue plus a value but only flag the value. `Employee ID EMP-40218` reports `EMP-40218`; the words "Employee ID" stay in the text so the redacted prompt still reads sensibly.

**Context gates.** Nine rules refuse to fire without a nearby cue, because their shape alone is too common:

| Rule | Required nearby |
| --- | --- |
| bare 9-digit SSN | `ssn`, `social security` |
| routing number | `routing`, `ABA`, `RTN`, `ACH`, `wire instructions` |
| EIN | `EIN`, `employer identification`, `federal tax id` |
| SWIFT/BIC | `swift`, `bic`, `beneficiary bank` |
| ICD code | `icd`, `diagnosis`, `dx`, `billing code` |
| UK postcode | `address`, `postcode`, `lives at` |
| ticket key | `jira`, `ticket`, `issue`, `sprint` |
| USCIS A-number | `uscis`, `immigration`, `alien registration` |
| Canadian SIN | `sin`, `social insurance` |

**Validators.** 22 rules run a validator after matching. Some are real checksums, some are structural, some downgrade rather than reject:

| Validator | Used by |
| --- | --- |
| Luhn (mod 10) + IIN brand table | payment cards, NPI |
| ISO 7064 mod-97-10 + country length table | IBAN |
| ABA weighted checksum (3·7·1) | US routing numbers |
| Verhoeff | Aadhaar |
| SSA structural rules (area ≠ 000/666/9xx, group ≠ 00, serial ≠ 0000) | SSN |
| Shannon entropy + character-class count | generic secrets |
| RFC-1918 / reserved-range test | IP addresses (downgraded, not dropped) |
| documentation-domain list | emails (downgraded to low) |
| known test-value list | sandbox cards like `4111 1111 1111 1111` (downgraded to low) |

A validator returning `false` drops the finding. Returning an object adjusts it: the Stripe rule downgrades `sk_test_…` to medium; the card rule downgrades published test cards to low and annotates them (`"Well-known Visa test card"`).

**The prose-versus-secret problem.** `password` followed by a word is extremely common in ordinary writing. The password rule requires the captured value to look machine-set rather than dictionary:

```
reject if it is a single plain word          ("requirements", "important")
reject if it is already masked or a template ("****", "[REDACTED]", "{{PASSWORD}}")
require a digit, or a symbol, or ≥2 capitals ("Autumn!Ledger42" ✓, "Summer2024" ✓)
```

That is why `never share your password with anyone` produces zero findings while `password Autumn!Ledger42` is critical.

### (c) Rule-based NER — `ner.js`

Names carry no checksum and no fixed shape, so they need a different approach. Statistical NER models are 5–50 MB, which is too large to ship into a content script that must respond in milliseconds. Instead the recogniser scores capitalisation shape against four signals:

| Signal | Weight |
| --- | --- |
| two or more consecutive capitalised words | +0.50 |
| a word matching the 462-name given-name gazetteer | +0.30 |
| preceded by an honorific (`Dr.`, `Ms.`, `Prof.`, `Rev.`…) | +0.45 |
| within ±45 characters of a person cue (`patient`, `employee`, `volunteer`, `client`, `my manager`, `attn`, `regards`…) | +0.25 |
| starts a sentence with no other signal | −0.20 |
| contains a non-name word or place name | −0.35 |

Threshold 0.50; ≥0.75 is high severity, below that medium. Runs are grown across name particles (`van`, `de`, `bin`, `O'`, `Mc`) so `Ana de Souza` is one entity.

Five hard rejections do most of the precision work:

1. every word is in the stop-list → not a name
2. every word is a place name → a location
3. the whole run is an acronym → `NHS`, `PDF`
4. the run *contains* an acronym without a gazetteer hit → `Roth IRA`, `Amazon AWS`
5. the run *starts* with a common noun without a gazetteer hit → `Project Halberd`, `Team Atlas`, `Room Nightingale`

The stop-list holds roughly 600 entries: structural English, weekdays, months, job titles and disciplines, document vocabulary, product and vendor names, corporate suffixes, and ~110 place names.

Organisations are only reported when a corporate suffix (`Ltd`, `Inc`, `GmbH`, `Foundation`, `Trust`…) appears **and** a confidentiality cue is nearby — `client`, `acquisition`, `NDA`, `contract`, `donor`. `Microsoft Excel` in a how-to question is not a disclosure; `our client Northwind Trading Ltd` is.

Every finding carries a `signals` array, so the UI can show the user exactly why something was treated as a name rather than asserting it.

### (d) Context scoring — `context.js`

Each candidate's confidence is then adjusted using a ±80 character window:

- **category cues** raise it, up to +0.15 — medical vocabulary near a medical finding, `login`/`token`/`.env` near a credential
- **placeholder cues** lower it by 0.22 — `example`, `sample`, `fictional`, `dummy`, `John Doe`, `acme`
- **"do not share" guidance** lowers it by 0.20 — text explaining that secrets should not be pasted is not itself a secret
- **general-question framing** lowers it by 0.12 — `what is…`, `how do I…`, `explain…`

One exception matters. 25 rules are marked `strongIdentifier`: vendor-prefixed keys (`sk-proj-…`, `ghp_…`, `AKIA…`) and checksum-validated identifiers. For these the placeholder penalty drops to 0.05, because a live API key sitting next to `api.example.com` is still a live API key. This is the difference between test case E-01 scoring 59 and scoring 75.

The same mechanism produces the educational-versus-clinical distinction:

| Text | Result |
| --- | --- |
| `What is type 2 diabetes and how is it usually treated?` | condition validator downgrades to low (0.30), question framing removes another 0.12 → 0.18, below the 0.35 report threshold → **0 findings** |
| `Patient Marcus Chen was diagnosed with type 2 diabetes` | no downgrade, medical context cues add confidence → **high severity, score 100** |

### (e) Policy layer — `policy.js`

The policy is a plain JSON object. It controls enabled categories, the two thresholds, per-category severity overrides, the placeholder style, the extension's interrupt threshold, and three kinds of organisation-specific rule:

```json
{
  "customTerms": ["Project Halberd", "Orchard release"],
  "internalDomains": ["riverside-trust.invalid"],
  "customRules": [{
    "label": "CASE_REF",
    "pattern": "\\bCR-\\d{6}\\b",
    "category": "people_records",
    "severity": "high",
    "why": "Identifies a live case file held under a confidentiality duty."
  }]
}
```

Custom rules are compiled into the same rule shape as the built-ins, so they participate in overlap resolution and scoring identically. An invalid admin regex is skipped rather than allowed to break scanning. Six presets ship: Balanced, Strict, Healthcare, Financial services, Engineering, Permissive.

### (f–g) Thresholds and overlap resolution

Two thresholds separate *seeing* from *changing*:

- **`reportThreshold`** (0.35) — appears in the findings list
- **`redactThreshold`** (0.50) — the redact box is pre-ticked

A borderline finding is therefore shown and explained but left in the text unless the user ticks it. Users are not asked to un-redact things the tool was never confident about.

Overlaps are then resolved by severity, then span length, then confidence. Length matters: a phone-shaped fragment inside an IBAN loses to the IBAN, and `4539 5781 0033 8448` beats the 9-digit run inside it.

### (h) Risk scoring — `risk.js`

```
raw   = Σ severityWeight × confidence × repeatDecay
floor = severityFloor(worst finding)
score = clamp(max(raw, floor), 0, 100)
```

- severity weights: critical 45, high 22, medium 9, low 3
- repeat decay `1 / (1 + repeats × 1.6)` — the same email address three times is barely worse than once
- severity floors: critical 75, high 45, medium 18, low 5, scaled down when the worst finding is itself low-confidence

The floor is what makes the score behave the way a human would: **one confident API key is always at least 75**, regardless of how short the prompt is. Without it, a one-line prompt containing a live credential would score lower than a long prompt full of names.

Bands: 0 safe · 1–24 low · 25–49 moderate · 50–74 high · 75–100 critical.

### (i) Redaction — `redact.js`

Redaction only ever touches the exact character spans of ticked findings, working from the end of the string backwards. Everything else is copied verbatim. This is why "does not over-redact" is a structural property rather than a tuning exercise: untouched text is *literally* untouched.

Placeholder identity is stable per `(label, normalised value)`, so `Sarah Whitfield` is `[NAME_1]` every time she appears and `Daniel Osei` is `[NAME_2]`. The assistant can still follow who did what.

Four styles: `[EMAIL_1]` numbered (default), `[EMAIL]` plain, partial mask (`j••••@•••.com`), and realistic pseudonyms (`Alex Rivera`) for cases where a natural-sounding document matters more than obvious redaction.

---

## 3. Performance

| Metric | Value |
| --- | --- |
| Mean scan, 36-case corpus | **1.5 ms** |
| Engine size (bundled, unminified) | 110 kB |
| Dependencies | 0 |
| Network calls | 0 |

Fast enough to run on every keystroke behind a 220 ms debounce, which is what makes the extension's real-time badge possible.

---

## 4. Verifying the offline claim

```bash
npm run verify:offline
```

Scans every shipped file in `engine/`, `assets/`, `extension/`, `tests/` and `index.html` for `fetch(`, `XMLHttpRequest`, `WebSocket(`, `EventSource(`, `navigator.sendBeacon`, `importScripts`, remote `import()`, remote module specifiers, and remote `<script>`/`<link>` tags. Any hit fails the build.

Belt and braces, the web app also ships:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'none'; …
```

and the extension declares `"permissions": ["storage"]` with an empty `host_permissions` array and `connect-src 'none'` on its own pages. You can confirm all of this from the Network tab: loading the page and scanning a prompt produces zero requests after the initial static assets.

---

## 5. AI usage in building this project

Claude (Anthropic) was used as a pair programmer throughout: drafting the rule set and gazetteers, writing the UI, and reviewing edge cases. Every regex, checksum implementation and threshold was then verified against the test corpus, and several AI-suggested rules were rejected or rewritten after they produced false positives on the benign corpus — the `Roth IRA`, `Project Halberd` and `password is important` cases in the test suite all come from that loop. No AI model is used at runtime; the shipped product contains no model and makes no inference calls.
