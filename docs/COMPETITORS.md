# Competitive landscape

Snapshot taken **12 November 2026** from each vendor's public website and store
listing. Prices and claims are theirs, quoted as published on that date; none of
it was verified by testing their products. Re-check before quoting any of this
externally.

## The short version

1. **"Runs locally" is not a differentiator.** Roughly a dozen extensions make
   the same promise, several of them open source.
2. **The enterprise vendors sell a different product**: a cloud console, endpoint
   agents and a sales-led contract. Their marketing has moved from chat boxes to
   AI agents, MCP servers and coding tools.
3. **The small extensions have very few users.** The problem is real; the demand
   for a consumer tool that solves it is unproven.
4. **Terminal hooks for coding agents already exist too**, as separate
   single-purpose projects.

Nobody in the small-tool tier combines all the surfaces behind one shared policy
file. That combination, not any single feature, is the gap this project aims at.
See [STRATEGY.md](STRATEGY.md).

## Tier 1 — enterprise AI security platforms

| Vendor | How they sell | What their site leads with | Site stack |
| --- | --- | --- | --- |
| [Harmonic Security](https://harmonic.security) | "Book a demo"; no public prices | Classifying every AI task, browser and desktop control, governance for agents | Webflow, HubSpot |
| [Nightfall AI](https://www.nightfall.ai) | Per user per year, price on request | "Control data movement across AI agents, MCP servers, endpoints, and SaaS" | Webflow, HubSpot |
| [Prompt Security](https://www.prompt.security) | Demo-led | Enterprise AI security platform | Webflow, HubSpot |
| [Strac](https://www.strac.io) | "Book a demo" | SaaS, endpoint and browser DLP; lists HIPAA, PCI-DSS, ISO 27001, SOC 2 | Webflow |
| [anonym.company](https://anonym.company) | "Request demo" | Browser extension plus desktop client, MDM deployment, 273 entity types | Custom |

What they have that this project does not: compliance certifications, named
customers, sales and support staff, central dashboards, and coverage beyond the
browser through installed agents. A team of one cannot out-trust them on
credentials. Their weakness for a small firm is the buying process: a demo call,
a contract and a per-seat annual price.

Consolidation is fast. Trade press counted about 40 AI-security acquisitions in
the first three quarters of 2026, against 10 in all of the year before
([Dark Reading](https://www.darkreading.com/cybersecurity-analytics/ai-scramble-cybersecurity-ma-boom)).

## Tier 2 — small local extensions (the direct competitors)

| Product | Price as published | Notable |
| --- | --- | --- |
| [ChatDataMask](https://chatdatamask.com/) | Free; Pro $7.99/month | Masks and **restores** values locally; country packs for national IDs |
| [RedactPII](https://redactpiitools.com/) | Free (3 pastes a day, email sign-up); Pro $8/month; team plan announced at $14/seat/month | Uses on-device language models; 20 categories |
| [LLM Guard](https://llmguard.net/) | Free, open source | Regex and keyword rules |
| [PasteSecure](https://chromewebstore.google.com/detail/pastesecure-%E2%80%93-pii-redacti/ebolpbgeaeammpddffibagpobicfnhoc) | Store listing | Redact or tokenize before paste |
| [PrivacyScrubber](https://chromewebstore.google.com/detail/privacyscrubber-%E2%80%94-pii-red/pimoejgefeilajmmbpghifdmhdlkgjol) | Store listing | Client-side; the listing showed 105 users |
| [Hush PII Guard](https://github.com/gabi200/hush-pii-guard) | Open source | Redacts, then shows real values back on screen only |
| [Privacy Guardrail (DFKI)](https://github.com/dfki-dsa/pii-guardrail-browser-extension/) | Open source | Rust/WASM recognisers, optional in-browser transformer model |
| [Privy](https://github.com/Mominadar/privy) | Open source | Local models, checksum-verified one-time download |

Where they are ahead of this project today:

- **Restore in the browser.** ChatDataMask and Hush put the real values back
  into the assistant's answer. Here that exists only on the command line (v1.4.0).
- **Model-based detection.** RedactPII, Privy and Privacy Guardrail run small
  language models on the device. This engine is rules, checksums and word lists.
  It is fast and explainable, and it will miss things a model would catch.
- **They are already in the store.** This extension is not yet approved.

## Tier 3 — hooks for coding agents

| Project | What it does |
| --- | --- |
| [sensitive-canary](https://github.com/coo-quack/sensitive-canary) | Claude Code hooks; rules drawn from gitleaks and TruffleHog; allow tags |
| [claude-code-privacy-guard](https://github.com/datumbrain/claude-code-privacy-guard) | Blocks prompts with secrets or PII; offers a cleaned copy in the block message |
| [claude-code-redaction-hooks](https://github.com/l-mb/claude-code-redaction-hooks) | Separate block, redact and observe modes |

All of them share one platform limit: a prompt hook can block a prompt but
cannot rewrite it, and it does not see files pulled in by @-mention
([Claude Code hooks reference](https://code.claude.com/docs/en/hooks)). The hook
in this repository has the same limits.

## The numbers people quote

- The widely repeated "77% of employees paste data into AI tools" comes from a
  LayerX report, and coverage of the same report gives a different base: about
  18% of enterprise employees paste into AI tools, with over half of those
  pastes containing corporate information
  ([eSecurity Planet](https://www.esecurityplanet.com/news/shadow-ai-chatgpt-dlp/)).
  Do not put the 77% figure on the website.
- Most other statistics in circulation are vendor aggregations without a
  primary source. None are used in this project's marketing.
