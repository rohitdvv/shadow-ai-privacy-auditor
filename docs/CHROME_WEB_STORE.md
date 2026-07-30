# Publishing to the Chrome Web Store

Everything you need to submit the extension. The build, copy, privacy policy and
screenshots are all prepared for you — the only steps that require **you** are the
one-time $5 developer registration and the upload (both need your Google account).

---

## 0. Before you start (one-time)

1. Go to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole).
2. Sign in with the Google account you want to own the listing.
3. Pay the **one-time US$5 registration fee** and accept the developer agreement.
   *(Claude cannot do this step — it needs your login and payment.)*

## 1. Build the upload package

```bash
npm run build:extension        # regenerate the engine bundle
npm run store:package          # writes shadow-ai-privacy-auditor-extension.zip
```

If you don't have the `store:package` script, zip it manually from the repo root:

```bash
cd extension && zip -r ../shadow-ai-privacy-auditor-extension.zip . -x "*.DS_Store" && cd ..
```

The zip must have `manifest.json` at its **top level** (this one does).

## 2. Create the listing

In the dashboard: **Add new item → upload the zip.** Then fill in the fields below.

### Store listing

| Field | Value |
| --- | --- |
| **Name** | Shadow AI Privacy Auditor |
| **Summary** (≤132 chars) | Warns you before you paste names, IDs, passwords or health data into ChatGPT, Claude, Gemini & Copilot. 100% on-device. |
| **Category** | Productivity |
| **Language** | English |

### Detailed description (paste as-is)

```
Stop leaking sensitive information to AI chatbots — before you hit send.

Shadow AI Privacy Auditor watches the message box on the AI sites you already use
(ChatGPT, Claude, Gemini, Microsoft Copilot, Perplexity and more). As you type, it
scores your prompt 0–100, points out anything risky — names, emails, phone numbers,
SSNs, payment cards, API keys, passwords, medical details, client records,
confidential business info — and, with one click, replaces those parts with safe
placeholders so you can still get a useful answer.

Everything runs on your device.
• No account, no servers, no analytics.
• Your prompt text is never uploaded, logged, or sent anywhere — not even to us.
• The extension requests only "storage" permission and zero host permissions.
• Its manifest blocks all network access (connect-src 'none'), so it is technically
  incapable of transmitting your text.

How it works
• A live score pill appears above the message box.
• Click "Fix" to redact in place instantly, or open the panel to review each finding
  (with a plain-English reason) and choose what to keep.
• Pick how values are replaced: numbered tags, masks, or natural-looking pseudonyms
  so the prompt still reads normally.
• A risky send (Enter or the send button) pauses so you can review first.

Built for individuals who want a seatbelt for the careless paste, and for teams that
need a guardrail against unsanctioned AI use becoming a reportable data breach.

Open source: https://github.com/rohitdvv/shadow-ai-privacy-auditor
```

### Privacy

| Field | Value |
| --- | --- |
| **Single purpose** | Detect and redact sensitive information in the user's text on AI chat sites, locally, before it is sent. |
| **`storage` justification** | Store the user's own settings and a count-only activity log on their device. |
| **Content-script / site access justification** | Read the message composer on a fixed list of AI chat sites to scan it locally and warn the user before sending. No host permissions are requested. |
| **Remote code** | No. All code is packaged in the extension. |
| **Data collection disclosures** | Select **"does not collect"** for every category — nothing is transmitted off the device. |
| **Privacy policy URL** | https://rohitdvv.github.io/shadow-ai-privacy-auditor/privacy.html |

### Assets to upload

- **Icon:** `extension/icons/icon128.png` (already in the package).
- **Screenshots (1280×800):** generate with `npm run store:shots` — they land in `dist/store-shots/`. Recommended order:
  1. `shot-pill.png` — "It rates every prompt inline, right where you type."
  2. `shot-panel.png` — "Review each finding and get a safe version in one click."
  3. `shot-clean.png` — "Fix it instantly — cleaned, on your device."
  4. `shot-welcome.png` — "Works automatically on ChatGPT, Claude, Gemini & more."

## 3. Submit for review

Save the draft, then **Submit for review**. Review typically takes a few hours to a
few days. You'll get an email when it's published.

## 4. After publishing

Update the "Add to Chrome" links to point at your live store URL:

- `index.html` — the hero **Add to Chrome** button / `#dlExtension` link in the modal
- `README.md` — the top install link

---

### Notes on review-friendliness (already handled)

- Manifest V3, `permissions: ["storage"]`, `host_permissions: []`.
- No remote code, no `eval`, extension-page CSP is `script-src 'self'; connect-src 'none'`.
- Single, clearly-stated purpose that matches the permissions requested.
- A public privacy policy that says, truthfully, that nothing is collected.
