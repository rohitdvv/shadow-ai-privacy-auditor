#!/usr/bin/env node
/**
 * shadow-ai — the Shadow AI Privacy Auditor engine on the command line.
 *
 *   shadow-ai scan    [file...]          report sensitive data (stdin if no file)
 *   shadow-ai redact  [file] --vault f   print a safe version; remember the originals
 *   shadow-ai restore [file] --vault f   put the originals back into an AI answer
 *   shadow-ai hook claude-code           Claude Code UserPromptSubmit hook
 *
 * Same engine and same policy file as the browser extension. Reads files and
 * stdin, writes stdout: there is no network code here, and CI enforces that
 * (`npm run verify:offline`).
 */
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, POLICY_PRESETS } from '../engine/index.js';
import { emptyVault, parseVault, redactWithVault, restore } from './vault.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const POLICY_FILE = '.shadow-ai.json';
const BYPASS_TOKEN = '#allow-sensitive';
const EXIT = { ok: 0, findings: 1, usage: 2 };

class UsageError extends Error {}

const HELP = `shadow-ai — find and redact sensitive data before it reaches an AI assistant.
Everything runs on this machine. No network code.

Usage
  shadow-ai scan [file...]              Report findings. Reads stdin when no file is given.
  shadow-ai redact [file] [--vault f]   Print the safe version. --vault remembers the originals.
  shadow-ai restore [file] --vault f    Put the originals back into an AI answer.
  shadow-ai hook claude-code            Block risky prompts in Claude Code (UserPromptSubmit hook).

Options
  --policy <file>     Policy JSON (exported from the web app or extension settings).
  --preset <name>     ${Object.keys(POLICY_PRESETS).join(' | ')}
  --fail-on <level>   scan: exit 1 on "block" (default), "warn" or "any" finding.
  --json              scan: machine-readable output.
  --show-values       scan: print detected values in full. Off by default so secrets
                      do not end up in terminal history or CI logs.
  --strict            hook: block the prompt if the hook itself fails.
  -o, --output <file> redact / restore: write to a file instead of stdout.
  -h, --help          Show this help.     -v, --version   Show the version.

Policy lookup: --policy, then --preset, then the nearest ${POLICY_FILE} in this
directory or a parent, then the built-in default.

Exit codes: 0 nothing at or above --fail-on · 1 findings · 2 usage or I/O error.`;

/* ---------------------------------------------------------------- args --- */

const VALUE_FLAGS = new Set(['--policy', '--preset', '--fail-on', '--vault', '--output']);
const BOOL_FLAGS = new Set(['--json', '--show-values', '--strict', '--help', '--version']);
const ALIASES = { '-h': '--help', '-v': '--version', '-o': '--output' };

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = ALIASES[argv[i]] || argv[i];
    if (arg === '-' || !arg.startsWith('-')) { positional.push(arg); continue; }
    if (BOOL_FLAGS.has(arg)) { flags[arg.slice(2)] = true; continue; }
    if (VALUE_FLAGS.has(arg)) {
      const value = argv[++i];
      if (value === undefined) throw new UsageError(`${arg} needs a value`);
      flags[arg.slice(2)] = value;
      continue;
    }
    throw new UsageError(`unknown option ${argv[i]}`);
  }
  return { flags, positional };
}

/* -------------------------------------------------------------- policy --- */

function findProjectPolicy(startDir) {
  let dir = resolve(startDir);
  for (;;) {
    const candidate = join(dir, POLICY_FILE);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * A policy file is the JSON the web app and extension export. It may also name
 * a preset to start from: { "preset": "strict", "customTerms": [...] }.
 * The engine bounds and validates everything in it (rule counts, regex safety).
 */
function loadPolicyFile(path) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new UsageError(`cannot read policy ${path}: ${e.message}`);
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new UsageError(`policy ${path} is not a JSON object`);
  const { preset, ...rest } = raw;
  if (preset !== undefined && !Object.prototype.hasOwnProperty.call(POLICY_PRESETS, preset)) {
    throw new UsageError(`policy ${path}: unknown preset "${preset}"`);
  }
  return { ...(preset ? POLICY_PRESETS[preset] : {}), ...rest };
}

function resolvePolicy(flags, cwd, fallbackPreset) {
  if (flags.policy) return { policy: loadPolicyFile(resolve(cwd, flags.policy)), source: flags.policy };
  if (flags.preset) {
    if (!Object.prototype.hasOwnProperty.call(POLICY_PRESETS, flags.preset)) {
      throw new UsageError(`unknown preset "${flags.preset}". Choose: ${Object.keys(POLICY_PRESETS).join(', ')}`);
    }
    return { policy: POLICY_PRESETS[flags.preset], source: `preset ${flags.preset}` };
  }
  const project = findProjectPolicy(cwd);
  if (project) return { policy: loadPolicyFile(project), source: project };
  if (fallbackPreset) return { policy: POLICY_PRESETS[fallbackPreset], source: `preset ${fallbackPreset}`, fallback: true };
  return { policy: undefined, source: 'built-in default' };
}

/* ------------------------------------------------------------------ io --- */

function readInput(path) {
  try {
    return readFileSync(!path || path === '-' ? 0 : path, 'utf8');
  } catch (e) {
    throw new UsageError(`cannot read ${path || 'stdin'}: ${e.message}`);
  }
}

function writeOutput(flags, text) {
  if (flags.output) writeFileSync(flags.output, text);
  else process.stdout.write(text);
}

/** Enough to recognise a value, never enough to reuse it. */
function preview(value) {
  const v = String(value).replace(/\s+/g, ' ');
  if (v.length < 8) return '•'.repeat(v.length);
  return `${v.slice(0, 2)}${'•'.repeat(Math.min(v.length - 4, 12))}${v.slice(-2)}`;
}

function publicFinding(f, showValues) {
  return {
    label: f.label,
    title: f.title,
    category: f.category,
    severity: f.severity,
    confidence: Math.round(f.confidence * 100) / 100,
    line: f.line,
    start: f.start,
    end: f.end,
    willRedact: f.redact,
    ...(showValues ? { value: f.value } : { preview: preview(f.value) }),
  };
}

const LEVEL = { send: 0, warn: 1, block: 2 };

function shouldFail(result, failOn) {
  if (failOn === 'any') return result.findings.length > 0 || result.truncated;
  return LEVEL[result.verdict.action] >= LEVEL[failOn];
}

/* ------------------------------------------------------------ commands --- */

function cmdScan({ flags, positional }) {
  const failOn = flags['fail-on'] || 'block';
  if (!['block', 'warn', 'any'].includes(failOn)) throw new UsageError('--fail-on must be block, warn or any');
  const { policy, source } = resolvePolicy(flags, process.cwd());
  const inputs = positional.length ? positional : ['-'];
  const reports = [];
  let failed = false;

  for (const input of inputs) {
    const result = scan(readInput(input), { policy });
    if (shouldFail(result, failOn)) failed = true;
    reports.push({
      file: input === '-' ? '<stdin>' : input,
      score: result.risk.score,
      action: result.verdict.action,
      headline: result.verdict.headline,
      truncated: result.truncated,
      findings: result.findings.map((f) => publicFinding(f, flags['show-values'])),
    });
  }

  if (flags.json) {
    process.stdout.write(`${JSON.stringify({ policy: source, failed, reports }, null, 2)}\n`);
  } else {
    for (const r of reports) {
      console.log(`${r.file}: ${r.headline} (risk ${r.score}/100, ${r.findings.length} finding${r.findings.length === 1 ? '' : 's'})`);
      for (const f of r.findings) {
        const shown = flags['show-values'] ? f.value : f.preview;
        console.log(`  ${f.severity.padEnd(8)} ${f.label.padEnd(22)} line ${String(f.line).padEnd(5)} ${shown}  ${f.title}`);
      }
    }
    console.log(`policy: ${source}`);
  }
  return failed ? EXIT.findings : EXIT.ok;
}

function loadVault(path) {
  if (!existsSync(path)) return emptyVault();
  try {
    return parseVault(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new UsageError(`cannot read vault ${path}: ${e.message}`);
  }
}

function saveVault(path, vault) {
  // The vault holds the real values: owner-only, including when it already existed.
  writeFileSync(path, `${JSON.stringify(vault, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function cmdRedact({ flags, positional }) {
  if (positional.length > 1) throw new UsageError('redact takes one file (or stdin)');
  const { policy } = resolvePolicy(flags, process.cwd());
  const result = scan(readInput(positional[0]), { policy });
  if (result.truncated) {
    // Never emit a "safe version" of text that was only partly checked.
    throw new UsageError('input is too long to check completely (over 200,000 characters). Split it and redact each part.');
  }
  const before = flags.vault ? loadVault(flags.vault) : emptyVault();
  const { text, vault, replaced } = redactWithVault(result.text, result.findings, before);
  if (flags.vault) saveVault(flags.vault, vault);
  writeOutput(flags, text);
  console.error(`shadow-ai: redacted ${replaced} value${replaced === 1 ? '' : 's'}${flags.vault ? `; originals saved to ${flags.vault} (keep it private)` : ''}`);
  return EXIT.ok;
}

function cmdRestore({ flags, positional }) {
  if (!flags.vault) throw new UsageError('restore needs --vault <file> (written by `shadow-ai redact --vault`)');
  if (!existsSync(flags.vault)) throw new UsageError(`vault ${flags.vault} does not exist`);
  if (positional.length > 1) throw new UsageError('restore takes one file (or stdin)');
  const { text, restored, missing } = restore(readInput(positional[0]), loadVault(flags.vault));
  writeOutput(flags, text);
  console.error(`shadow-ai: restored ${restored} placeholder${restored === 1 ? '' : 's'}${missing.length ? `; not in vault: ${missing.join(', ')}` : ''}`);
  return EXIT.ok;
}

/**
 * Claude Code UserPromptSubmit hook.
 *
 * Contract (https://code.claude.com/docs/en/hooks): the prompt arrives as JSON
 * on stdin. To block, print {"decision":"block","reason":…} and exit 0; the
 * reason is shown to the user and is not sent to the model. To allow, print
 * nothing: anything on stdout would be added to the model's context.
 *
 * A hook cannot rewrite the prompt, so the safe version is offered in the block
 * message for the user to resend. It also does not see files pulled in with
 * @-mentions; those are read by the agent, not typed by the user.
 */
function cmdHook({ flags, positional }) {
  if (positional[0] !== 'claude-code') throw new UsageError('usage: shadow-ai hook claude-code');

  let event;
  try {
    event = JSON.parse(readInput('-'));
  } catch (e) {
    throw new Error(`hook input is not JSON: ${e.message}`);
  }
  const prompt = typeof event.prompt === 'string' ? event.prompt : '';
  const cwd = typeof event.cwd === 'string' && existsSync(event.cwd) ? event.cwd : process.cwd();

  // With no policy of its own, the hook stops only critical findings: keys,
  // passwords, government and payment identifiers. Coding prompts name
  // colleagues all the time, and a hook that blocks "ask Priya to review this"
  // gets uninstalled. A team that wants more commits a .shadow-ai.json, and
  // then that policy's own block threshold applies.
  const { policy, source, fallback } = resolvePolicy(flags, cwd, 'engineering');
  const isBlocked = (r) => (fallback
    ? r.truncated || r.findings.some((f) => f.severity === 'critical')
    : r.verdict.action === 'block');
  const result = scan(prompt, { policy });
  if (!isBlocked(result)) return EXIT.ok;

  const bypassAllowed = !(policy && policy.allowBypass === false);
  if (bypassAllowed && prompt.includes(BYPASS_TOKEN)) return EXIT.ok;

  const lines = [`Shadow AI blocked this prompt (risk ${result.risk.score}/100).`];
  if (result.truncated) {
    lines.push('It is longer than 200,000 characters, so it could not be checked completely. Send it in smaller parts.');
  } else {
    for (const f of result.findings.slice(0, 12)) {
      lines.push(`  ${f.severity.padEnd(8)} ${f.title} on line ${f.line}: ${preview(f.value)}`);
    }
    if (result.findings.length > 12) lines.push(`  … and ${result.findings.length - 12} more`);
    // Redact every finding, including low-confidence ones, then re-check: only
    // offer a "safe version" that this same hook would actually let through.
    const everything = result.findings.map((f) => ({ ...f, redact: true }));
    const safe = redactWithVault(result.text, everything).text;
    const passes = !isBlocked(scan(safe, { policy }));
    if (passes && safe.length <= 6000) lines.push('', 'Safe version to send instead:', safe);
    else if (passes) lines.push('', 'Run `shadow-ai redact` on the text to get a safe version.');
    else lines.push('', 'Automatic redaction is not enough here. Remove the items above by hand.');
  }
  if (bypassAllowed) lines.push('', `To send it unchanged, add ${BYPASS_TOKEN} to the prompt.`);
  lines.push(`(policy: ${fallback ? 'default, critical findings only' : source})`);

  process.stdout.write(`${JSON.stringify({ decision: 'block', reason: lines.join('\n') })}\n`);
  return EXIT.ok;
}

/* ---------------------------------------------------------------- main --- */

function main(argv) {
  const [command, ...rest] = argv;
  if (!command || command === '-h' || command === '--help' || command === 'help') { console.log(HELP); return EXIT.ok; }
  if (command === '-v' || command === '--version') {
    console.log(JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version);
    return EXIT.ok;
  }
  const args = parseArgs(rest);
  if (args.flags.help) { console.log(HELP); return EXIT.ok; }

  switch (command) {
    case 'scan': return cmdScan(args);
    case 'redact': return cmdRedact(args);
    case 'restore': return cmdRestore(args);
    case 'hook':
      try {
        return cmdHook(args);
      } catch (e) {
        // A missing or broken policy is a UsageError: exit 2, which blocks the
        // prompt. A damaged policy file must not quietly switch protection off.
        if (e instanceof UsageError) throw e;
        // Exit 2 blocks the prompt in Claude Code; exit 1 lets it through with a warning.
        console.error(`shadow-ai hook failed: ${e.message}${args.flags.strict ? ' — prompt blocked (--strict).' : ' — prompt was NOT checked.'}`);
        return args.flags.strict ? 2 : 1;
      }
    default: throw new UsageError(`unknown command "${command}"`);
  }
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  if (!(e instanceof UsageError)) throw e;
  console.error(`shadow-ai: ${e.message}\nRun \`shadow-ai --help\` for usage.`);
  process.exitCode = EXIT.usage;
}
