# Security Policy

Shadow AI Privacy Auditor is a privacy tool, so we treat security reports as the
highest-priority work in the project.

## Supported versions

Only the latest release receives fixes. The Chrome extension auto-updates from
the Chrome Web Store; the web app is always the latest deploy.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/rohitdvv/shadow-ai-privacy-auditor/security/advisories/new).

Include what you found, the steps to reproduce it, and the impact you believe it
has. You can expect an acknowledgement within 3 business days and a fix or a
mitigation plan within 30 days for confirmed issues. We are happy to credit you.

## What counts as a vulnerability

The product's core promise is that **prompt text never leaves the device**. In
scope, in order of severity:

1. Any path by which prompt text, a detected value, or anything derived from it
   reaches a network, the host page, or storage that syncs.
2. A way to bypass detection or the send interception — e.g. text that is never
   scanned, or a send that skips review when policy says it should block.
3. A way for a web page to read or drive the extension's UI, or to tamper with
   its policy or activity log.
4. Denial of service of a user's AI chat tab through the extension (e.g.
   catastrophic regex backtracking).
5. Supply-chain issues in the build or release pipeline.

Missed detections of a particular data format are quality bugs, not
vulnerabilities — please open a regular issue for those.

## How the guarantees are enforced

| Guarantee | Enforcement |
| --- | --- |
| No network access | Extension pages ship `connect-src 'none'`; the web app ships the same CSP; CI (`npm run verify:offline`) fails on any `fetch`, XHR, WebSocket, beacon or remote reference in shipped code. |
| Minimal permissions | `permissions: ["storage"]`, `host_permissions: []`, content scripts on a fixed site list only. |
| Page isolation | The in-page UI lives in a **closed** shadow root inside the content script's isolated world. |
| No unscanned sends | Text beyond the scan limit is reported as "too long to check" and blocked, never as safe; it is never rewritten (no silent truncation). |
| No ReDoS from policies | Custom regexes are statically rejected if they contain nested quantifiers, repeated alternation or backreferences; all policy lists are size-bounded. |
| Untrusted messages | The service worker accepts messages only from its own extension and coerces every audit field to a known shape. |
| Supply chain | Zero runtime dependencies; CI actions pinned to commit SHAs and kept current by Dependabot; CodeQL `security-extended` on every push. |

Every row above is covered by a regression test in `tests/security.js`.
