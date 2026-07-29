# Known limitations and future improvements

Written honestly. A privacy tool that overstates what it catches is worse than no tool, because it converts caution into confidence.

---

## The headline caveat

**This is a safety net, not a guarantee.** It reduces accidental disclosure; it cannot certify that a prompt is safe. A confident "0 findings" means *the engine found nothing it recognises*, which is not the same as *there is nothing sensitive here*. The UI is deliberately worded as "nothing sensitive detected", never "this is safe".

---

## Detection limitations

### 1. Meaning is invisible to the engine

The engine matches form, not intent. Sensitive information carried entirely by meaning is missed:

- *"We're going to lose the Henderson account next quarter"* — commercially damaging, no marker word, no identifier shape. `Henderson` is caught as a possible name; the disclosure itself is not.
- *"He's the one who was in rehab last year"* — a health disclosure with no name and no clinical vocabulary in a form the gazetteer holds.
- Paraphrased secrets: *"the password is the founder's dog's name plus the year"*.

**Future:** a small on-device classifier (e.g. a quantised ONNX model in a Web Worker) as an optional second pass, kept local so the offline guarantee holds.

### 2. Names are the weakest category

Rule-based NER trades recall for precision. Known gaps:

- A name with no gazetteer hit, no honorific and no role cue scores 0.50 exactly and can fall below threshold under a strict policy.
- Single first names in isolation (*"ask Ravi about it"*) are only caught when a role cue is present.
- Non-Latin scripts (Arabic, Devanagari, Han, Cyrillic) have no capitalisation signal at all and are effectively invisible to the recogniser.
- A capitalised product or feature name occasionally reaches the threshold. `Project Halberd`, `Roth IRA` and `Amazon AWS` are handled by explicit rules; the long tail is not.

**Future:** ship a compact multilingual person-name model; add script-aware heuristics for non-Latin names; let users add names to a local allow-list.

### 3. English-first

Regexes are largely language-independent, but the gazetteers, medical vocabulary, business vocabulary and context cues are English. A prompt written in Spanish or Hindi will have its cards, IBANs and API keys caught, and very little else.

**Future:** externalise gazetteers into per-language JSON, starting with Spanish, French, German and Hindi; add locale-specific identifier rules (CURP, NIF, NHS number, Cartão de Cidadão).

### 4. Identifier coverage is broad but not exhaustive

Implemented: US, UK, Canada, India and IBAN-region identifiers. Not implemented: most national ID formats, driver-licence formats per US state, tax numbers for most EU countries, medical device and lot numbers, and DEA/state licence numbers.

Some rules are necessarily heuristic. Passport and driver-licence numbers have no checksum and no universal format, so they are only caught next to their cue word. A passport number written bare in a list will be missed.

### 5. Structured and non-text input

- CSV, JSON and tabular pastes are scanned as text, so column headers are treated as ordinary words. A column of raw account numbers with no header cue can be missed.
- Images, screenshots, PDFs and file attachments are **not** analysed. This matters: uploading a screenshot of a spreadsheet bypasses the tool entirely.
- Code is scanned for credentials but not for embedded business logic or proprietary algorithms.

**Future:** structured-input detection (recognise CSV/JSON shape and scan per column); optional local OCR via Tesseract WASM for pasted images.

### 6. Adversarial evasion

The engine is not designed to resist a user who wants to defeat it. Splitting a key across lines, base64-encoding it, or writing an SSN as words defeats pattern matching. This is an accepted trade-off: the threat model is *accidental* disclosure by a well-meaning person, not exfiltration by a determined insider.

### 7. Long inputs

Input is truncated at 200,000 characters to keep the UI responsive. Beyond that the tail is not scanned. The UI reports truncation, but a very large paste is a scenario where the tool degrades.

---

## Extension limitations

1. **Selectors track third-party DOMs.** ChatGPT, Gemini and Claude change their composer markup without notice. The extension uses layered selectors and a focus-based fallback, but a redesign can temporarily break the badge or the send interception. There is no automated way to detect this from inside the extension.
2. **Send interception is best-effort.** Enter and the visible send button are both intercepted at capture phase, but a site could dispatch a send from a path the extension does not observe (a slash command, a voice input, a keyboard shortcut we do not know about).
3. **Rewriting rich editors.** ProseMirror, Lexical and Quill maintain internal state. The extension uses `execCommand('insertText')` so the editor's own pipeline processes the change; if a site blocks that path, formatting can be lost when a prompt is redacted.
4. **Chromium only.** Manifest V3 as written targets Chrome and Edge. Firefox needs a small manifest shim; Safari needs a separate wrapper.
5. **Not enterprise-managed yet.** Policy syncs through `chrome.storage.sync`, which follows the user's profile. Real enterprise deployment needs `chrome.storage.managed` and a policy schema pushed by the admin console.

---

## Product and process limitations

- **No shared team reporting.** The audit log is deliberately local and content-free, which also means an organisation cannot aggregate it. Any future central reporting must keep the content-free property, or it recreates the exact database this tool exists to avoid.
- **Not legal or compliance advice.** Category explanations reference GDPR, HIPAA and PCI-DSS to help users understand the stakes. They are context, not a compliance assessment, and no output should be treated as evidence of compliance.
- **Thresholds are judgement calls.** 0.35 to report and 0.50 to redact were tuned against a 36-case corpus and 45 benign prompts written by the same people who wrote the rules. That is a real bias. A larger, independently authored corpus would be the single most valuable next investment.
- **Test corpus size.** 36 cases and 45 benign prompts is enough to catch regressions and demonstrate the precision/recall trade-off. It is not enough to publish a headline accuracy number with confidence. The 100% figures in this repository mean "passes its own suite", and should be read that way.

---

## Prioritised roadmap

| Priority | Item | Why |
| --- | --- | --- |
| 1 | Larger, independently written test corpus | Everything else is measured against it |
| 2 | `chrome.storage.managed` + admin policy schema | Unblocks real enterprise deployment |
| 3 | Optional on-device classifier for meaning-carried disclosures | Closes the biggest detection gap |
| 4 | Multilingual gazetteers and identifier rules | Most of the world is not English |
| 5 | Structured-input (CSV/JSON) mode | Common real-world paste shape |
| 6 | Firefox and Safari builds | Coverage |
| 7 | Local OCR for pasted screenshots | Closes the image bypass |
| 8 | User-managed allow-list of known-safe names and terms | Removes the residual false positives users actually meet |
