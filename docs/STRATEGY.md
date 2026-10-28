# Strategy — from hackathon project to a business

How a top-tier product team would take Shadow AI Privacy Auditor to market.
Pricing figures below are **hypotheses to validate with customers**, not facts.

---

## 1. The one thing (the Jobs test)

> **The only AI data-loss guard that provably cannot see your data.**

Most enterprise DLP for AI works by routing prompts through a proxy or a
vendor's cloud to inspect them. That asks a company to hand a third party the
exact data it is trying to protect. This product does the opposite: detection
runs inside the browser, the extension manifest sets `connect-src 'none'`, the
code is open source, and CI proves there is no network code. **The privacy
guarantee is not a feature — it is the moat and the sales pitch.** Every other
decision should protect it.

## 2. Work backwards from the customer (the Bezos test)

| Customer | Their real pain | What they buy |
| --- | --- | --- |
| Individual professional | "I pasted a client's details into ChatGPT and felt sick." | A seatbelt. Free. |
| Team lead / small company | "I can't tell staff to stop using AI, but I can't afford a leak." | Shared rules for the team. |
| CISO / compliance officer | "Shadow AI use is a reportable-breach risk under GDPR/HIPAA/PCI." | Org-wide enforcement + evidence for auditors. |

The money is in the third row. The first row is distribution.

## 3. Business model — monetise without a backend

| Tier | Price (hypothesis) | What you get |
| --- | --- | --- |
| **Free** | $0, forever | Full detection, Fix, review panel, local log. No ads, no data, ever. |
| **Team** | ~$3–5 / user / month | Shared policy file, custom rules & restricted terms, policy presets per team. |
| **Enterprise** | annual contract | Force-install via Google Admin / Intune, **managed policy** (shipped in v1.3.0), "always on" lock, compliance report export, priority support, security review pack. |

**The clever part — licensing with zero network calls.** Enterprise features can
be unlocked by a *signed license* pushed through Chrome managed storage, the same
channel as the managed policy. The extension embeds a public key and verifies
the signature offline (Ed25519 via WebCrypto). No licence server, no phone-home,
and the `connect-src 'none'` promise stays intact. This is the feature to build
next if the business model is validated.

## 4. Distribution (first-principles)

Ranked by leverage, cheapest first:

1. **Chrome Web Store** — the consumer funnel and the credibility badge.
2. **Microsoft Edge Add-ons** — same Manifest V3 code, near-zero porting cost,
   and Edge users are exactly the Microsoft 365 / Copilot companies that buy DLP.
3. **Chrome Enterprise / Google Admin force-install** — this is where contracts
   come from. The managed-policy schema added in v1.3.0 is the prerequisite.
4. **Firefox Add-ons** — MV3 is supported; small API differences.

Motion: **bottom-up then top-down.** Individuals install it free → it catches
something real → they forward it to IT → IT standardises with the managed policy.

## 5. Trust stack — what to do before asking for money

| Step | Why | Cost |
| --- | --- | --- |
| Keep the core open source | Anyone can verify the privacy claim | done |
| `SECURITY.md` + private vulnerability reporting | Expected by every security buyer | done (enable reporting in repo settings) |
| CodeQL, SHA-pinned CI, Dependabot | Supply-chain hygiene | done |
| Reproducible builds + published checksums | Prove the store package = the source | checksums done |
| Independent penetration test | The single most persuasive document for a CISO | paid, later |
| SOC 2 | Only needed once there is a backend; today there is no data to certify | defer |

## 6. Measuring success without telemetry

The product promises no tracking, so it cannot phone home — and must not start.
Measure through channels that respect that:

- **Store dashboard:** installs, weekly users, uninstalls, ratings, reviews.
- **Enterprise customers:** they export the local, content-free activity CSV
  themselves — their evidence for auditors, our proof of value.
- **Opt-in feedback:** a "was this flag useful?" link to a survey, never automatic.

North-star metric: **sensitive items caught and redacted per active user per
week** (reported by customers from their own logs).

## 7. Risks, honestly

| Risk | Mitigation |
| --- | --- |
| AI vendors add native PII warnings | Be cross-platform (13+ sites), org-policy-driven and vendor-neutral — a vendor cannot police its competitors' sites. |
| False positives annoy users into uninstalling | Precision is a first-class metric; the 45-prompt benign corpus must stay at 0 false positives. |
| Store policy or review changes | Minimal permissions, clear single purpose, honest listing. |
| Trademark complaints over naming AI products | Describe compatibility ("works with ChatGPT…"), never imply affiliation. |
| A security flaw in a privacy product | Regression-tested guarantees (`tests/security.js`), disclosure policy, fast patch cadence. |

## 8. 30 / 60 / 90 days

- **30:** Store approval. Edge Add-ons listing. Five design-partner companies
  using the managed policy for free in exchange for feedback.
- **60:** Signed offline licence + Team tier. Compliance report export.
- **90:** First paid enterprise pilot. Independent penetration test. Firefox.
