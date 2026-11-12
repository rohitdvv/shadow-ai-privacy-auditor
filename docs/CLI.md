# Command line and coding-agent hook

The same detection engine as the browser extension, for the terminal. It reads
files and standard input and writes standard output. There is no network code;
CI fails the build if any appears (`npm run verify:offline`).

Requires Node.js 18 or later. No dependencies.

## Install

```bash
npm install -g github:rohitdvv/shadow-ai-privacy-auditor#v1.4.0
```

Pin a tag, as above, so an update is something you choose. To try it without
installing:

```bash
npx -y github:rohitdvv/shadow-ai-privacy-auditor#v1.4.0 scan notes.txt
```

## Scan

```bash
shadow-ai scan prompt.txt
pbpaste | shadow-ai scan
shadow-ai scan --json src/fixtures/*.txt
```

Output shows what was found and where, with each value masked so it does not
land in terminal history or CI logs. Add `--show-values` to print them.

Exit code `1` means the text would be blocked under the policy; `0` means it
would not. `--fail-on warn` or `--fail-on any` makes the check stricter, which
is useful in a pre-commit hook or CI step.

## Redact and restore

Send a safe version to the assistant, then put the real values back into its
answer:

```bash
shadow-ai redact email.txt --vault session.vault.json > safe.txt
# paste safe.txt into the assistant, save its reply as reply.txt
shadow-ai restore reply.txt --vault session.vault.json
```

The vault maps each placeholder to its original value. Reusing the same vault
across a conversation keeps placeholders stable: the same person is `[NAME_1]`
in every message.

**The vault contains the real values.** It is written readable by you only
(mode 600). Keep it out of version control and delete it when the conversation
is over.

## Claude Code hook

Blocks a prompt that contains a secret or identifier before it is sent, and
shows a safe version to send instead. Add to `~/.claude/settings.json` (all
projects) or `.claude/settings.json` (one project):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "shadow-ai hook claude-code --strict", "onFailure": "block" }
        ]
      }
    ]
  }
}
```

Behaviour:

- **Default:** blocks critical findings only (API keys, passwords, private
  keys, government and payment identifiers). Names and emails pass, because
  coding prompts mention colleagues constantly.
- **With a `.shadow-ai.json`** in the project or a parent directory, that
  policy's block threshold applies instead, for example `{ "preset": "strict" }`.
- **Sending anyway:** add `#allow-sensitive` to the prompt. Set
  `"allowBypass": false` in the policy to remove that option.
- **Failure:** `--strict` and `"onFailure": "block"` make the hook fail closed.
  Without them, a hook error or timeout lets the prompt through unchecked.
- A broken policy file always blocks, so a damaged file cannot switch
  protection off unnoticed.

Limits, which apply to every prompt hook on this platform:

- The hook can block a prompt but **cannot rewrite it**. You resend the safe
  version yourself.
- It checks what you type and paste. It does **not** see files the agent reads,
  including files you @-mention.

## One policy file for the team

`.shadow-ai.json` uses the same format the web app and extension export. It can
start from a preset:

```json
{
  "preset": "strict",
  "customTerms": ["Project Halberd"],
  "internalDomains": ["riverside-trust.invalid"],
  "allowBypass": false
}
```

Presets: `balanced`, `strict`, `healthcare`, `finance`, `engineering`,
`permissive`. Commit the file to a repository and everyone who works in it gets
the same rules.

A policy file can loosen rules as well as tighten them, so review changes to it
like any other code. Custom patterns are checked before use and catastrophic
ones are refused.

## Verify what you installed

Release zips are built by CI with signed provenance:

```bash
gh attestation verify shadow-ai-privacy-auditor-extension.zip --repo rohitdvv/shadow-ai-privacy-auditor
```

The extension zip is also reproducible: `npm run store:package` on the tagged
source produces the same SHA-256 as the published file.
