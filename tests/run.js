#!/usr/bin/env node
/**
 * Test runner.
 *
 *   node tests/run.js                 pretty console report
 *   node tests/run.js --write-report  also regenerate docs/TEST_RESULTS.md
 *   node tests/run.js --verbose       print every finding for every case
 *   node tests/run.js --only S-01,R-05
 *
 * Exit code is non-zero when any assertion fails, so this works as a CI gate.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, redact, SEVERITY_RANK, CATEGORY_META } from '../engine/index.js';
import { CASES } from './cases.js';
import { BENIGN_PROMPTS } from './benign.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const argv = process.argv.slice(2);
const WRITE_REPORT = argv.includes('--write-report');
const VERBOSE = argv.includes('--verbose');
const onlyArg = argv.find((a) => a.startsWith('--only'));
const ONLY = onlyArg ? new Set(onlyArg.split('=')[1].split(',')) : null;

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m', grey: '\x1b[90m',
};

function covers(findings, needle) {
  return findings.some((f) => f.value.includes(needle) || needle.includes(f.value) || (f.matchText || '').includes(needle));
}

function runCase(tc) {
  const result = scan(tc.text);
  const redaction = redact(result.text, result.findings, { style: result.policy.redactionStyle });
  const failures = [];
  const e = tc.expect || {};

  for (const cat of e.categories || []) {
    if (!result.findings.some((f) => f.category === cat)) {
      failures.push(`expected a ${CATEGORY_META[cat]?.short || cat} finding, got none`);
    }
  }

  if (Array.isArray(e.categories) && e.categories.length === 0 && result.findings.length > 0) {
    failures.push(`expected zero findings, got ${result.findings.length}: ${result.findings.map((f) => `"${f.value}" (${f.ruleId})`).join(', ')}`);
  }

  for (const needle of e.mustFlag || []) {
    if (!covers(result.findings, needle)) failures.push(`missed: "${truncate(needle)}"`);
  }

  for (const needle of e.mustNotFlag || []) {
    if (covers(result.findings, needle)) {
      const who = result.findings.find((f) => f.value.includes(needle) || needle.includes(f.value));
      failures.push(`over-flagged: "${truncate(needle)}" via rule ${who?.ruleId}`);
    }
  }

  if (e.unchanged && redaction.text !== tc.text) {
    failures.push(`text was modified but should be unchanged (${redaction.replacements.length} replacement(s))`);
  }

  if (e.maxSeverity) {
    const cap = SEVERITY_RANK[e.maxSeverity];
    const worse = result.findings.filter((f) => SEVERITY_RANK[f.severity] > cap);
    if (worse.length) failures.push(`severity too high: ${worse.map((f) => `${f.ruleId}=${f.severity}`).join(', ')} (max ${e.maxSeverity})`);
  }

  if (typeof e.minScore === 'number' && result.risk.score < e.minScore) {
    failures.push(`risk score ${result.risk.score} < expected minimum ${e.minScore}`);
  }
  if (typeof e.maxScore === 'number' && result.risk.score > e.maxScore) {
    failures.push(`risk score ${result.risk.score} > expected maximum ${e.maxScore}`);
  }

  for (const needle of e.redactedContains || []) {
    if (!redaction.text.includes(needle)) failures.push(`redacted output missing "${needle}"`);
  }
  for (const needle of e.redactedNotContains || []) {
    if (redaction.text.includes(needle)) failures.push(`redacted output still contains "${truncate(needle)}"`);
  }

  return { tc, result, redaction, failures, pass: failures.length === 0 };
}

function truncate(s, n = 60) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Escape for a Markdown table cell inside a code span: backslashes first, then pipes and backticks. */
function mdCell(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/`/g, "'");
}

/* ------------------------------ run ------------------------------ */

const selected = CASES.filter((tc) => !ONLY || ONLY.has(tc.id));
const results = selected.map(runCase);
const passed = results.filter((r) => r.pass);
const failed = results.filter((r) => !r.pass);

/* Aggregate detection metrics from the mustFlag / mustNotFlag assertions. */
let tp = 0, fn = 0, fp = 0, tn = 0;
for (const r of results) {
  const e = r.tc.expect || {};
  for (const needle of e.mustFlag || []) (covers(r.result.findings, needle) ? tp++ : fn++);
  for (const needle of e.mustNotFlag || []) (covers(r.result.findings, needle) ? fp++ : tn++);
  if (Array.isArray(e.categories) && e.categories.length === 0) {
    if (r.result.findings.length === 0) tn++; else fp += r.result.findings.length;
  }
}
const precision = tp + fp ? tp / (tp + fp) : 1;
const recall = tp + fn ? tp / (tp + fn) : 1;
const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

const totalMs = results.reduce((n, r) => n + r.result.stats.durationMs, 0);

/* Benign corpus: every prompt must produce zero findings. */
const benign = BENIGN_PROMPTS.map((text) => {
  const result = scan(text);
  return { text, result, clean: result.findings.length === 0 };
});
const benignDirty = benign.filter((b) => !b.clean);
const falsePositiveRate = benignDirty.length / benign.length;

/* ---------------------------- console ---------------------------- */

console.log(`\n${C.bold}Shadow AI Privacy Auditor — detection test suite${C.reset}`);
console.log(`${C.grey}${selected.length} fictional cases · engine runs fully offline${C.reset}\n`);

for (const r of results) {
  const badge = r.pass ? `${C.green}PASS${C.reset}` : `${C.red}FAIL${C.reset}`;
  const score = String(r.result.risk.score).padStart(3);
  console.log(`${badge}  ${C.bold}${r.tc.id}${C.reset}  score ${score}  ${C.dim}${r.result.findings.length} finding(s)${C.reset}  ${r.tc.name}`);
  for (const f of r.failures) console.log(`      ${C.red}✗${C.reset} ${f}`);
  if (VERBOSE) {
    for (const f of r.result.findings) {
      console.log(`      ${C.cyan}·${C.reset} ${f.ruleId} ${C.dim}[${f.severity} ${f.confidence.toFixed(2)}]${C.reset} "${truncate(f.value, 48)}"`);
    }
  }
}

console.log(`\n${C.bold}Benign corpus (false-positive harness)${C.reset}`);
if (benignDirty.length === 0) {
  console.log(`  ${C.green}All ${benign.length} ordinary prompts returned zero findings.${C.reset}`);
} else {
  for (const b of benignDirty) {
    console.log(`  ${C.red}FP${C.reset} "${truncate(b.text, 70)}"`);
    for (const f of b.result.findings) console.log(`       ${C.dim}${f.ruleId} → "${f.value}"${C.reset}`);
  }
}

console.log(`\n${C.bold}Summary${C.reset}`);
console.log(`  cases      ${passed.length}/${selected.length} passed`);
console.log(`  benign     ${benign.length - benignDirty.length}/${benign.length} clean  ${C.dim}(false-positive rate ${(falsePositiveRate * 100).toFixed(1)}%)${C.reset}`);
console.log(`  precision  ${(precision * 100).toFixed(1)}%   ${C.dim}(${tp} true positives, ${fp} false positives)${C.reset}`);
console.log(`  recall     ${(recall * 100).toFixed(1)}%   ${C.dim}(${fn} missed)${C.reset}`);
console.log(`  F1         ${(f1 * 100).toFixed(1)}%`);
console.log(`  speed      ${totalMs.toFixed(1)} ms total, ${(totalMs / selected.length).toFixed(2)} ms/case\n`);

/* ---------------------------- report ----------------------------- */

if (WRITE_REPORT) {
  const md = buildReport();
  mkdirSync(resolve(ROOT, 'docs'), { recursive: true });
  writeFileSync(resolve(ROOT, 'docs/TEST_RESULTS.md'), md, 'utf8');
  console.log(`${C.green}Wrote docs/TEST_RESULTS.md${C.reset}\n`);
}

function buildReport() {
  const lines = [];
  lines.push('# Test Results');
  lines.push('');
  lines.push('_Generated by `npm run test:report`. Every case below uses **fictional data created for this project** — no real personal, medical, financial, immigration, employee, volunteer or organisational data appears anywhere in this repository._');
  lines.push('');
  lines.push(`Run date: ${new Date().toISOString().slice(0, 10)}  `);
  lines.push(`Engine: local-only, zero network calls  `);
  lines.push(`Cases: **${selected.length}** (${CASES.filter((c) => c.kind === 'safe').length} safe · ${CASES.filter((c) => c.kind === 'risky').length} risky · ${CASES.filter((c) => c.kind === 'edge').length} edge)`);
  lines.push('');
  lines.push('## Headline metrics');
  lines.push('');
  lines.push('| Metric | Result |');
  lines.push('| --- | --- |');
  lines.push(`| Cases passed | ${passed.length} / ${selected.length} |`);
  lines.push(`| Benign prompts returning zero findings | ${benign.length - benignDirty.length} / ${benign.length} |`);
  lines.push(`| False-positive rate on benign corpus | ${(falsePositiveRate * 100).toFixed(1)}% |`);
  lines.push(`| Precision | ${(precision * 100).toFixed(1)}% |`);
  lines.push(`| Recall | ${(recall * 100).toFixed(1)}% |`);
  lines.push(`| F1 | ${(f1 * 100).toFixed(1)}% |`);
  lines.push(`| Mean scan time | ${(totalMs / selected.length).toFixed(2)} ms |`);
  lines.push('');
  lines.push('Precision and recall are measured against explicit `mustFlag` / `mustNotFlag` assertions in `tests/cases.js`, plus a zero-finding assertion on every safe case.');
  lines.push('');
  lines.push('## Case-by-case results');
  lines.push('');
  lines.push('| ID | Type | Scenario | Score | Findings | Categories | Result |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const r of results) {
    const cats = [...new Set(r.result.findings.map((f) => CATEGORY_META[f.category]?.short || f.category))].join(', ') || '—';
    lines.push(`| ${r.tc.id} | ${r.tc.kind} | ${r.tc.name} | ${r.result.risk.score} | ${r.result.findings.length} | ${cats} | ${r.pass ? '✅ pass' : '❌ fail'} |`);
  }
  lines.push('');
  lines.push('## Worked examples');
  lines.push('');
  for (const id of ['S-01', 'S-04', 'R-01', 'R-05', 'R-10', 'R-13', 'R-16', 'R-19', 'E-01', 'E-05']) {
    const r = results.find((x) => x.tc.id === id);
    if (!r) continue;
    lines.push(`### ${r.tc.id} — ${r.tc.name}`);
    lines.push('');
    lines.push('**Input**');
    lines.push('');
    lines.push('```text');
    lines.push(r.tc.text);
    lines.push('```');
    lines.push('');
    if (r.result.findings.length) {
      lines.push('**Findings**');
      lines.push('');
      lines.push('| Detected | Category | Severity | Confidence | Rule |');
      lines.push('| --- | --- | --- | --- | --- |');
      for (const f of r.result.findings) {
        lines.push(`| \`${mdCell(truncate(f.value.replace(/\n/g, ' ⏎ '), 44))}\` | ${CATEGORY_META[f.category]?.short} | ${f.severity} | ${f.confidence.toFixed(2)} | \`${f.ruleId}\` |`);
      }
      lines.push('');
    } else {
      lines.push('**Findings:** none.');
      lines.push('');
    }
    lines.push(`**Risk score:** ${r.result.risk.score}/100 — ${r.result.risk.band.label}`);
    lines.push('');
    lines.push('**Redacted output**');
    lines.push('');
    lines.push('```text');
    lines.push(r.redaction.changed ? r.redaction.text : `${r.tc.text}\n\n(unchanged — nothing needed redaction)`);
    lines.push('```');
    lines.push('');
  }
  if (failed.length) {
    lines.push('## Failing assertions');
    lines.push('');
    for (const r of failed) {
      lines.push(`- **${r.tc.id}** — ${r.failures.join('; ')}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

process.exit(failed.length || benignDirty.length ? 1 : 0);
