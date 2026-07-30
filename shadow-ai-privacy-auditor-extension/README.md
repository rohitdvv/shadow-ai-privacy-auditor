# Chrome extension

Manifest V3. Watches the message composer on AI chat sites, scans it locally as you type, and interrupts a send that crosses your policy's risk threshold.

## Install (unpacked)

```bash
npm run build:extension     # generates vendor/engine.bundle.js and the icons
```

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → choose this `extension/` folder
4. Open any supported site and start typing

## Supported sites

ChatGPT · Gemini · Claude · Microsoft Copilot (web and M365) · Bing Chat · Perplexity · Poe · Grok · Mistral Chat · Hugging Face Chat

## What it does

| | |
| --- | --- |
| **Badge** | A pill above the composer shows the live risk score and finding count, updated ~220 ms after you stop typing |
| **Interception** | Enter and the send button are both captured. If the score is at or above `blockAtScore`, the send is stopped and a review panel opens |
| **Review panel** | Every finding with its category, severity and a one-line reason, tick boxes to keep individual items, and a live preview of the redacted prompt |
| **Redact and send** | Rewrites the composer through the editor's own input pipeline, then resumes the send |
| **Popup** | Counts of what has been caught, a master on/off switch |
| **Options** | Presets, category toggles, thresholds, placeholder style, custom terms, internal domains, custom regex rules, a live tester, and CSV export of the activity log |

## Permissions

```json
"permissions": ["storage"],
"host_permissions": []
```

`storage` only. No host permissions, no tabs, no scripting, no webRequest. The content script is declared statically against a fixed site list, so it cannot be injected anywhere else.

`content_security_policy` on extension pages is `script-src 'self'; connect-src 'none'`, which means the options and popup pages cannot make a network request even if a bug tried to.

## Privacy

- Prompt text is **never** sent anywhere — not to a server, not to the service worker, not to the page.
- The content script and the service worker exchange only counts: risk score, per-category and per-severity totals, the host, and which button you pressed.
- The activity log lives in `chrome.storage.local` and never syncs.
- Your **policy** lives in `chrome.storage.sync` so it follows your Chrome profile. It contains configuration only.
- `localStorage` is deliberately not used by the content script, because a content script shares `localStorage` with the host page — writing there would leak extension state into ChatGPT's own storage.

## Files

```
manifest.json                MV3 manifest
background.js                service worker: config, audit, badge
content/content.js           composer discovery, scanning, interception, shadow-DOM UI
content/content.css          shadow-host isolation only
popup/                       toolbar popup
options/                     full policy editor + live tester
shared/storage.js            chrome.storage helpers
vendor/engine.bundle.js      GENERATED — do not edit, see tools/build-extension.mjs
icons/                       GENERATED — see tools/make-icons.mjs
```

`vendor/engine.bundle.js` is a flattened build of `/engine/*.js`. Edit the engine, then re-run `npm run build:extension`; CI fails if the committed bundle is stale.
