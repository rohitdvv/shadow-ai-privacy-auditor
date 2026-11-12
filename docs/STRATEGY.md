# Strategy

Rewritten 12 November 2026 after a review of the market
([COMPETITORS.md](COMPETITORS.md)). Prices and timelines here are
**hypotheses to test with customers**, not facts.

---

## 1. What the market review changed

The earlier plan rested on "it runs locally, so the vendor never sees your
data". About a dozen products make that same promise, and several are open
source. It is the entry ticket, not the pitch.

Three other facts shape the plan:

- **The enterprise vendors are out of reach on trust.** They have
  certifications, customer logos and sales teams. They also sell by demo call
  and annual contract, which shuts out small firms.
- **The consumer tier is crowded and tiny.** Prices sit at $0–8 a month and one
  store listing showed 105 users. Individuals mostly do not pay for this.
- **AI use is leaving the chat box.** The enterprise vendors now lead with
  agents, MCP servers and coding tools. A browser extension alone covers a
  shrinking share of where prompts are written.

## 2. The bet

> **One policy for every place your team prompts. No server. Check it yourself.**

A small team writes one policy file. The same file drives the browser extension,
the command line and the coding-agent hook, using the same detection engine in
all three. Nothing is hosted, so there is no account, no console and no vendor
to trust with data. The build is reproducible and signed, so the "no server"
claim can be checked instead of believed.

No single piece of this is unique. The combination is, as of the review date:
the small tools each cover one surface, and the vendors that cover all of them
do it with a cloud console.

## 3. Who it is for

**Teams of roughly 10–200 people doing regulated or confidential work without a
security department**: law firms, clinics, accountancies, recruiters, agencies
and software consultancies bound by client NDAs.

| | Enterprise platform | Consumer extension | This project |
| --- | --- | --- | --- |
| Buying process | Demo call, contract | Install | Install, or commit one file |
| Shared team rules | Yes, in a cloud console | Mostly no | Yes, in a file the team owns |
| Covers terminal and coding agents | Yes, with installed agents | No | Yes, CLI and hook |
| Vendor infrastructure in the path | Yes | Varies | None |
| Certifications, support desk | Yes | No | No |

The last row is the honest cost of this position. A buyer who needs a SOC 2
report or a support contract should buy from the first column.

## 4. Product surfaces (v1.4.0)

| Surface | Status | Policy source |
| --- | --- | --- |
| Chrome extension | Built; store review pending; not yet tested on the live AI sites | Settings import, or pushed by an admin (managed policy) |
| Command line (`shadow-ai scan / redact / restore`) | Built and tested | `--policy`, or `.shadow-ai.json` in the project |
| Claude Code hook | Built and tested against the documented hook contract | Same `.shadow-ai.json` |
| Web checker | Live | Same JSON, import and export |

`.shadow-ai.json` committed to a repository is the distribution mechanism for
teams: every developer who clones the repo gets the team's rules with no admin
console and no rollout.

## 5. Business model

| Tier | Price (hypothesis) | What it adds |
| --- | --- | --- |
| **Free** | $0 | Everything above, for anyone. Open source. |
| **Team** | $4–6 per user per month | Maintained policy packs per profession (legal, healthcare, finance), a signed policy so members cannot weaken it, an evidence report for client and auditor questionnaires. |
| **Enterprise** | Annual | Force-install and managed policy (shipped), priority fixes, a security review pack. |

Paid features unlock with a **signed licence file verified offline**, delivered
the same way as the policy. No licence server, so the no-network promise holds.
This is not built yet and should not be built until five teams are using the
free version.

Realistic expectation: free tools in this category earn little directly. The
free tier exists to earn installs and credibility; revenue, if any, comes from
teams that need evidence for someone else (a client, an insurer, a regulator).

## 6. Distribution, cheapest first

1. **Developers.** The CLI and hook install from GitHub in one command, and a
   committed policy file spreads the tool through a team by itself.
2. **Chrome Web Store**, then **Edge Add-ons** (same code; Edge shops are the
   Microsoft 365 firms in the target segment).
3. **Professional communities**: a short, specific guide per profession ("using
   ChatGPT at a law firm without breaching privilege") beats generic marketing.
4. **Design partners**: five named teams using it free in return for feedback
   and, if they agree, a public quote. Logos are the trust signal this project
   lacks most.

## 7. Trust, earned not claimed

| Step | Status |
| --- | --- |
| Open source core | Done |
| CI check that shipped code has no network calls | Done |
| Reproducible extension build with a published hash | Done in v1.4.0 |
| Signed build provenance (anyone can verify the zip came from this repo's CI) | Done in v1.4.0 |
| Security policy, code scanning, pinned CI actions | Done |
| Published detection benchmark others can run | Partly: the corpus is public but small and self-written |
| Independent security review | Not done; the most persuasive document for a buyer |
| Named users | None yet |

## 8. Weaknesses to be straight about

- **Detection is rules, not a model.** Several competitors run on-device
  language models. Rules are fast and explainable and will miss free-text
  disclosures a model would catch.
- **The accuracy numbers are self-graded.** 36 risky cases and 114 ordinary
  prompts, all written by this project. Before v1.4.0 the engine flagged the
  word "add" as a health condition and about one in three everyday prompts
  raised a false warning; the earlier corpus was too easy to notice. Expect
  more of these in real use.
- **The extension has not been exercised on the live AI sites**, only on a
  local mock page.
- **No restore in the browser yet**; competitors have it.
- **The coding-agent hook cannot rewrite a prompt or see @-mentioned files.**
  That is a platform limit shared by every such hook.
- **Zero users.** Everything in section 5 is untested.

## 9. Next 30 / 60 / 90 days

- **30:** Store approval. Real-site test pass on each supported AI site. Edge
  listing. Restore in the extension. First two design-partner teams.
- **60:** Policy packs for two professions. Evidence report. Five design partners.
- **90:** Decide, from what those five teams actually use, whether a paid Team
  tier is worth building. If not, keep it as a free open-source tool and stop.
