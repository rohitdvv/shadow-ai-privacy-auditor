#!/usr/bin/env node
/**
 * End-to-end tests for the `shadow-ai` command line. Each test runs the real
 * binary as a child process, exactly as a shell or Claude Code would.
 *
 * All values are fictional (see tests/cases.js for the data policy).
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'cli', 'shadow-ai.mjs');
const TMP = mkdtempSync(join(tmpdir(), 'shadow-ai-cli-'));

const SECRET = 'AKIA1234567890ABCD99';
const RISKY = `Email John Carter at john.carter84@gmail.com, SSN 512-88-1044, and rotate the AWS key ${SECRET}.`;

function run(args, { input = '', cwd = TMP } = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { input, cwd, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const hook = (event, args = [], opts) => run(['hook', 'claude-code', ...args], { input: JSON.stringify(event), ...opts });

const results = [];
function test(name, fn) {
  try { fn(); results.push([true, name]); } catch (e) { results.push([false, name, e]); }
}

/* scan --------------------------------------------------------------------- */

test('scan: clean text exits 0', () => {
  const r = run(['scan'], { input: 'The project meeting is scheduled for 3:00 PM.' });
  assert.equal(r.code, 0);
  assert.match(r.out, /Nothing sensitive detected/);
});

test('scan: blocked text exits 1 and never prints the secret', () => {
  const r = run(['scan'], { input: RISKY });
  assert.equal(r.code, 1);
  assert.match(r.out, /AWS_ACCESS_KEY/);
  for (const raw of [SECRET, '512-88-1044', 'john.carter84@gmail.com']) {
    assert.ok(!r.out.includes(raw) && !r.err.includes(raw), `leaked ${raw}`);
  }
});

test('scan --json: valid JSON, previews only', () => {
  const r = run(['scan', '--json'], { input: RISKY });
  const data = JSON.parse(r.out);
  assert.equal(data.failed, true);
  assert.equal(data.reports[0].action, 'block');
  assert.ok(data.reports[0].findings.every((f) => f.preview && f.value === undefined));
  assert.ok(!r.out.includes(SECRET));
});

test('scan --show-values: prints values only when asked', () => {
  assert.ok(run(['scan', '--show-values'], { input: RISKY }).out.includes(SECRET));
});

test('scan --fail-on: warn-level text passes by default and fails on request', () => {
  const input = 'Please forward this to John Carter.';
  assert.equal(run(['scan'], { input }).code, 0);
  assert.equal(run(['scan', '--fail-on', 'warn'], { input }).code, 1);
  assert.equal(run(['scan', '--fail-on', 'any'], { input }).code, 1);
});

test('scan: reads several files and reports each', () => {
  writeFileSync(join(TMP, 'clean.txt'), 'Explain the difference between a merge and a rebase.');
  writeFileSync(join(TMP, 'risky.txt'), RISKY);
  const r = run(['scan', 'clean.txt', 'risky.txt']);
  assert.equal(r.code, 1);
  assert.match(r.out, /clean\.txt: Nothing sensitive detected/);
  assert.match(r.out, /risky\.txt: Do not send as written/);
});

test('scan: over-long input is reported as unchecked, not clean', () => {
  const r = run(['scan'], { input: 'a '.repeat(150_000) });
  assert.equal(r.code, 1);
  assert.match(r.out, /too long/i);
});

test('usage errors exit 2', () => {
  assert.equal(run(['scan', '--nope']).code, 2);
  assert.equal(run(['frobnicate']).code, 2);
  assert.equal(run(['scan', 'does-not-exist.txt']).code, 2);
  assert.equal(run(['scan', '--preset', 'nope'], { input: 'x' }).code, 2);
});

/* redact / restore --------------------------------------------------------- */

test('redact then restore returns the original text exactly', () => {
  const vault = join(TMP, 'round-trip.vault.json');
  const safe = run(['redact', '--vault', vault], { input: RISKY });
  assert.equal(safe.code, 0);
  assert.equal(safe.out, 'Email [NAME_1] at [EMAIL_1], SSN [SSN_1], and rotate the AWS key [AWS_ACCESS_KEY_1].');
  assert.ok(!safe.err.includes(SECRET));
  const back = run(['restore', '--vault', vault], { input: safe.out });
  assert.equal(back.out, RISKY);
});

test('the vault is owner-only and placeholders stay stable across messages', () => {
  const vault = join(TMP, 'session.vault.json');
  run(['redact', '--vault', vault], { input: 'Email John Carter about the renewal.' });
  if (process.platform !== 'win32') assert.equal(statSync(vault).mode & 0o777, 0o600);
  const second = run(['redact', '--vault', vault], { input: 'Also cc Priya Shah and John Carter.' });
  assert.equal(second.out, 'Also cc [NAME_2] and [NAME_1].');
  const answer = run(['restore', '--vault', vault], { input: 'Done: [NAME_1] and [NAME_2] are both copied. [NAME_7] is unknown.' });
  assert.equal(answer.out, 'Done: John Carter and Priya Shah are both copied. [NAME_7] is unknown.');
  assert.match(answer.err, /not in vault: \[NAME_7\]/);
});

test('restore does not chain: a restored value that looks like a placeholder is left alone', () => {
  const vault = join(TMP, 'chain.vault.json');
  writeFileSync(vault, JSON.stringify({ version: 1, entries: { '[NAME_1]': '[NAME_2]', '[NAME_2]': 'Priya Shah' } }));
  assert.equal(run(['restore', '--vault', vault], { input: 'Hi [NAME_1]' }).out, 'Hi [NAME_2]');
});

test('restore ignores malformed vault entries and rejects non-vault files', () => {
  const vault = join(TMP, 'hostile.vault.json');
  writeFileSync(vault, JSON.stringify({ version: 1, entries: { 'the': 'INJECTED', '[NAME_1]': 'Priya Shah', '[X_1]': 42 } }));
  assert.equal(run(['restore', '--vault', vault], { input: 'the [NAME_1] and [X_1]' }).out, 'the Priya Shah and [X_1]');
  writeFileSync(join(TMP, 'not-a-vault.json'), '{"hello":1}');
  assert.equal(run(['restore', '--vault', 'not-a-vault.json'], { input: 'x' }).code, 2);
});

test('redact refuses text that is too long to check completely', () => {
  const r = run(['redact'], { input: 'a '.repeat(150_000) });
  assert.equal(r.code, 2);
  assert.equal(r.out, '');
});

/* policy ------------------------------------------------------------------- */

test('a project .shadow-ai.json is found from a subdirectory and applied', () => {
  const project = join(TMP, 'project');
  mkdirSync(join(project, 'src', 'deep'), { recursive: true });
  writeFileSync(join(project, '.shadow-ai.json'), JSON.stringify({ preset: 'strict', customTerms: ['Project Halberd'] }));
  const r = run(['scan', '--json'], { input: 'Summarise the Project Halberd timeline.', cwd: join(project, 'src', 'deep') });
  const data = JSON.parse(r.out);
  assert.match(data.policy, /\.shadow-ai\.json$/);
  assert.ok(data.reports[0].findings.length >= 1, 'custom term not flagged');
});

test('a policy with a catastrophic regex does not hang the CLI', () => {
  const policy = join(TMP, 'evil-policy.json');
  writeFileSync(policy, JSON.stringify({ customRules: [{ label: 'EVIL', pattern: '(a+)+$', category: 'org_confidential' }] }));
  const started = Date.now();
  const r = run(['scan', '--policy', policy], { input: `${'a'.repeat(40)}!` });
  assert.equal(r.code, 0);
  assert.ok(Date.now() - started < 5000, 'scan took too long');
});

/* Claude Code hook --------------------------------------------------------- */

test('hook: an ordinary coding prompt passes with empty stdout', () => {
  for (const prompt of [
    'Ask John Carter to refactor the parser module and add tests',
    'Please add tests for the login form and fix the Pull Request.',
    'Why does std::vector reallocate when I call push_back?',
  ]) {
    const r = hook({ prompt, cwd: TMP });
    assert.equal(r.code, 0, prompt);
    assert.equal(r.out, '', `stdout would be added to the model context: ${r.out}`);
  }
});

test('hook: a prompt with a secret is blocked without echoing it', () => {
  const r = hook({ prompt: `fix the deploy script, key is ${SECRET} and db password=Sup3rS3cret!x9`, cwd: TMP });
  assert.equal(r.code, 0);
  const decision = JSON.parse(r.out);
  assert.equal(decision.decision, 'block');
  assert.ok(!decision.reason.includes(SECRET) && !decision.reason.includes('Sup3rS3cret'));
  assert.match(decision.reason, /Safe version to send instead:\nfix the deploy script, key is \[AWS_ACCESS_KEY_1\]/);
});

test('hook: a project policy makes the hook stricter than the default', () => {
  const strict = join(TMP, 'strict-project');
  mkdirSync(strict, { recursive: true });
  writeFileSync(join(strict, '.shadow-ai.json'), JSON.stringify({ preset: 'strict' }));
  const prompt = 'Draft a note to John Carter at john.carter84@gmail.com';
  assert.equal(hook({ prompt, cwd: TMP }).out, '');
  assert.equal(JSON.parse(hook({ prompt, cwd: strict }).out).decision, 'block');
});

test('hook: the offered safe version would itself pass the hook', () => {
  const first = JSON.parse(hook({ prompt: `use ${SECRET} to call the API`, cwd: TMP }).out);
  const safe = first.reason.split('Safe version to send instead:\n')[1].split('\n\n')[0];
  assert.equal(hook({ prompt: safe, cwd: TMP }).out, '');
});

test('hook: #allow-sensitive lets the user send knowingly, unless policy forbids it', () => {
  const prompt = `use ${SECRET} #allow-sensitive`;
  assert.equal(hook({ prompt, cwd: TMP }).out, '');
  const locked = join(TMP, 'locked');
  mkdirSync(locked, { recursive: true });
  writeFileSync(join(locked, '.shadow-ai.json'), JSON.stringify({ preset: 'engineering', allowBypass: false }));
  const r = JSON.parse(hook({ prompt, cwd: locked }).out);
  assert.equal(r.decision, 'block');
  assert.ok(!r.reason.includes('To send it unchanged'));
});

test('hook: malformed input fails open by default and closed with --strict', () => {
  assert.equal(run(['hook', 'claude-code'], { input: 'not json' }).code, 1);
  assert.equal(run(['hook', 'claude-code', '--strict'], { input: 'not json' }).code, 2);
});

test('hook: a broken policy file blocks instead of silently disabling protection', () => {
  const broken = join(TMP, 'broken');
  mkdirSync(broken, { recursive: true });
  writeFileSync(join(broken, '.shadow-ai.json'), '{ not json');
  assert.equal(hook({ prompt: 'hello', cwd: broken }).code, 2);
});

/* report ------------------------------------------------------------------- */

rmSync(TMP, { recursive: true, force: true });

let failed = 0;
for (const [ok, name, err] of results) {
  console.log(`${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}`);
  if (!ok) { failed++; console.log(`      ${err.message}`); }
}
console.log(`\ncli  ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
