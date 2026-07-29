# Walkthrough video script (3–5 minutes)

Covers every point the brief requires: the detection approach, a risky example redacted, a safe example left alone, AI usage, and limitations.

**Before you record**

- `npm run serve`, open `http://localhost:4173` (or your deployed URL)
- Load the extension: `npm run build:extension` → `chrome://extensions` → Load unpacked → `extension/`
- Open a second tab on ChatGPT or Gemini, logged in, with an empty composer
- Have a terminal ready in the repo
- Clear the activity log so the counters start at zero

---

## 0:00 – 0:25 · The problem

> "People paste things into ChatGPT they would never email externally — a patient record, a `.env` file, a colleague's salary. It feels private because it looks like a chat window. It isn't.
>
> This is the Shadow AI Privacy Auditor. It reads your text before you send it, tells you what's risky and why, and gives you a version that's safe to send. It runs entirely in your browser — nothing you type ever leaves your machine."

*On screen: the web app, empty.*

---

## 0:25 – 1:15 · The safe example first

Type, don't paste:

```
The project meeting is scheduled for 3:00 PM.
```

> "Start with the harder half of the problem. A tool that redacts everything gets turned off in a week, so the first thing to show is what it *doesn't* do.
>
> Score zero. No findings. The safe version is byte-for-byte identical to the input."

Load the `Agenda with times, dates and room numbers` example:

> "Times, dates, room numbers, version numbers, percentages — the engine computes those as protected spans before any rule runs. Forty-five ordinary prompts in our test suite, zero false positives."

*Point at the "Nothing was changed" line under the output.*

---

## 1:15 – 2:20 · The risky example

Load `Clinical note with MRN, diagnosis and medication`:

```
Patient Marcus Chen (MRN 4482910) was diagnosed with type 2 diabetes and started on
metformin 500mg. Insurance member ID BCB8837421. NPI 1488736202.
```

> "Same tool, same second. Score 100 — critical, do not send.
>
> Six findings, grouped by category and colour-coded in the text. Each one says what it is, how confident the engine is, how it was found, and — this is the part that changes behaviour — *why it matters*. Not 'PII detected'. 'An MRN is a direct key into a patient's full clinical file and is protected health information under HIPAA.'"

Expand one **Why this was flagged**:

> "And it shows its working. This was matched by a pattern plus a validator — the NPI passed its Luhn check against the 80840 prefix, so it's a real provider identifier, not a random ten digits."

Scroll to the safe version:

> "Here's the output. Names, record numbers, the condition, the medication, the insurance ID — all replaced. `500mg` is untouched. The placeholders are numbered and stable, so if Marcus Chen appeared three times he'd be `[NAME_1]` all three times and the assistant can still follow the text."

Click **Keep** on one finding:

> "And you're in control. Keep anything you actually need — the output updates instantly."

Click **Copy safe text**.

---

## 2:20 – 3:05 · How detection works

*Optional: show `engine/patterns.js` briefly.*

> "Under the hood: seventy-two pattern rules with real validators — Luhn for cards, mod-97 for IBANs, Verhoeff for Aadhaar, the ABA checksum for routing numbers. Nine rules refuse to fire without a nearby cue word, so a bare nine-digit number is only an SSN if the word 'SSN' is next to it.
>
> Names have no checksum, so there's a rule-based recogniser: capitalisation shape, a 462-name gazetteer, honorifics, and role cues like 'patient' or 'volunteer' — with a six-hundred-word stop-list whose entire job is to stop it flagging 'Roth IRA' or 'Project Halberd' as people.
>
> Then a context scorer. 'What is type 2 diabetes?' scores zero — it's a general question. 'Patient Marcus Chen was diagnosed with type 2 diabetes' scores 100. Same words, different intent, and the engine can tell the difference."

Run in the terminal:

```bash
npm test
```

> "Thirty-six fictional test cases, forty-five benign prompts, all passing. Every value is invented — the card numbers and IBANs were generated to satisfy their checksums so the validators are genuinely exercised. No real data anywhere in this project."

---

## 3:05 – 3:55 · The browser extension

Switch to the ChatGPT tab. Type:

```
Employee ID EMP-40218, Ravi Deshmukh, was placed on a performance improvement plan.
His base salary is $86,500.
```

> "The web app is the demo. This is how you'd actually use it."

*Point at the badge above the composer.*

> "It's scanning as I type, locally, in about a millisecond and a half. Four findings, high risk."

Press **Enter**.

> "And it stops the send."

*The panel appears.*

> "Same findings, same explanations, and the safe version right there. I can untick anything I want to keep, then —"

Click **Redact and send**.

> "— it rewrites the composer and sends. One click, and a piece of HR data that was about to become permanent didn't."

Open the extension popup:

> "The popup shows what it's caught. And this is important: that log stores counts and categories only. Never your text, never a detected value, never leaves your browser. A privacy tool that builds a database of everyone's secrets has missed the point."

Open **Policy settings** briefly:

> "Six presets, per-category toggles, thresholds, and custom rules — an organisation can push its own codenames, internal domains and regexes as a JSON policy."

---

## 3:55 – 4:30 · AI usage and limitations

> "On AI usage: I built this with Claude as a pair programmer — drafting the rule set, the word lists and the UI. But every regex, checksum and threshold was verified against the test corpus, and several AI-suggested rules were rejected after they produced false positives. The 'Roth IRA' and 'password is important' test cases exist because early versions got them wrong.
>
> No AI model runs at inference time. There's no API call and no model in the shipped product — which is the point. Sending your text to a model to ask whether it's safe to send to a model is circular.
>
> Limitations, honestly: it matches form, not meaning. 'We're going to lose the Henderson account' is commercially sensitive and it won't catch it. It's English-first. It doesn't read images or PDFs, so a screenshot bypasses it entirely. And it's a safety net, not a guarantee — zero findings means nothing was recognised, not that nothing is there. All of that is written up in LIMITATIONS.md."

---

## 4:30 – 4:50 · Close

Run:

```bash
npm run verify:offline
```

> "One last thing. 'It all runs locally' is the central claim, so it's asserted, not promised: this fails the build if any shipped file contains fetch, XHR, a WebSocket, a beacon or a remote import. The web app also ships `connect-src 'none'`, so the browser blocks outbound requests itself.
>
> Working prototype, browser extension, live URL, full test suite, all local. Thanks for watching."

---

## Shot list

| Shot | Duration |
| --- | --- |
| Web app — safe sentence, score 0 | 0:25–1:15 |
| Web app — clinical note, findings, redacted output, keep toggle | 1:15–2:20 |
| Terminal — `npm test` (+ optional `patterns.js`) | 2:20–3:05 |
| ChatGPT — badge, interception panel, redact and send | 3:05–3:45 |
| Extension popup and options page | 3:45–3:55 |
| Talking head or slide — AI usage and limitations | 3:55–4:30 |
| Terminal — `npm run verify:offline` | 4:30–4:50 |

## Reminders

- Never show a real credential, even briefly. Every value on screen must come from `tests/cases.js`.
- Show the safe example **before** the risky one — precision is the differentiator.
- Say the word "why" out loud when showing a finding; the explanation is what the brief scores.
- Keep terminal font large enough to read at 720p.
