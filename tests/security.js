#!/usr/bin/env node
/**
 * Security regression tests. Each test pins down a loophole found in the
 * pre-release audit so it cannot quietly come back.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, redact, normalisePolicy, checkPatternSafety, POLICY_LIMITS } from '../engine/index.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const results = [];
async function test(name, fn) {
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e]); }
}

/* L1 — truncation must never read as safe, and never be written back --- */

await test('truncated input is blocked, not reported as safe', () => {
  const secret = 'AWS key AKIA1234567890ABCD99';
  const r = scan('a '.repeat(150_000) + secret);           // 300k chars, secret past the cap
  assert.equal(r.truncated, true);
  assert.equal(r.verdict.action, 'block');
  assert.match(r.verdict.headline, /too long/i);
});

await test('truncated input with no findings in the head is still blocked', () => {
  const r = scan('x'.repeat(250_000));
  assert.equal(r.truncated, true);
  assert.equal(r.findings.length, 0);
  assert.equal(r.verdict.action, 'block');
});

await test('normal-length input is unaffected', () => {
  const r = scan('The project meeting is scheduled for 3:00 PM.');
  assert.equal(r.truncated, false);
  assert.equal(r.verdict.action, 'send');
});

/* L2 — ReDoS: catastrophic custom patterns are rejected before compiling --- */

for (const bad of ['(a+)+$', '(\\w*)*x', '(x{1,}){2,}', '(a|ab)*c', '(?:x|xy)+z', '(a)\\1', 'a'.repeat(300)]) {
  await test(`unsafe pattern rejected: ${bad.slice(0, 24)}`, () => {
    assert.ok(checkPatternSafety(bad), `expected ${bad} to be rejected`);
  });
}

for (const good of ['\\bCR-\\d{6}\\b', '\\b(?:PRJ|OPS)-\\d+\\b', '[A-Z]{2}\\d{4}', 'case\\s+#?\\d{5}']) {
  await test(`safe pattern accepted: ${good}`, () => {
    assert.equal(checkPatternSafety(good), null);
  });
}

await test('normalisePolicy drops unsafe rules and keeps safe ones', () => {
  const p = normalisePolicy({ customRules: [{ pattern: '(a+)+$' }, { pattern: '\\bCR-\\d{6}\\b', label: 'CASE' }] });
  assert.equal(p.customRules.length, 1);
  assert.equal(p.customRules[0].label, 'CASE');
});

await test('a hostile policy cannot freeze scanning', () => {
  const policy = { customRules: [{ pattern: '(a+)+$' }, { pattern: '(a|aa)*b' }] };
  const started = performance.now();
  scan('a'.repeat(5_000) + '!', { policy });
  assert.ok(performance.now() - started < 1_000, 'scan took too long — ReDoS guard failed');
});

await test('policy lists are bounded', () => {
  const p = normalisePolicy({
    customTerms: Array.from({ length: 2_000 }, (_, i) => `Term number ${i}`),
    customRules: Array.from({ length: 200 }, (_, i) => ({ pattern: `\\bX${i}\\b` })),
    internalDomains: ['ok.example', 'not a domain', 'javascript:alert(1)'],
  });
  assert.ok(p.customTerms.length <= POLICY_LIMITS.customTerms);
  assert.ok(p.customRules.length <= POLICY_LIMITS.customRules);
  assert.deepEqual(p.internalDomains, ['ok.example']);
});

/* L4 — audit entries from content scripts are sanitised -------------------- */

await test('audit entries are coerced to a safe shape', async () => {
  let stored = {};
  globalThis.chrome = {
    storage: {
      local: {
        get: async () => ({ ...stored }),
        set: async (o) => { stored = { ...stored, ...o }; },
      },
    },
  };
  const { appendAudit } = await import('../extension/shared/storage.js');
  await appendAudit({
    score: 9_999, band: '<img src=x onerror=alert(1)>', action: 'pwned',
    byCategory: { contact: 2, '<script>': 5, __proto__: 1 },
    counts: { critical: -4, high: '3' }, totalFindings: 'lots', host: 'h'.repeat(999),
  });
  const [e] = stored.auditLog;
  assert.equal(e.score, 100);
  assert.equal(e.band, 'safe');
  assert.equal(e.action, 'scanned');
  assert.deepEqual(Object.keys(e.byCategory), ['contact']);
  assert.equal(e.counts.critical, 0);
  assert.equal(e.counts.high, 3);
  assert.equal(e.totalFindings, 0);
  assert.equal(e.host.length, 253);
});

/* Manifest / store guarantees --------------------------------------------- */

await test('manifest meets store + privacy guarantees', () => {
  const m = JSON.parse(readFileSync(resolve(ROOT, 'extension/manifest.json'), 'utf8'));
  assert.equal(m.manifest_version, 3);
  assert.ok(m.description.length <= 132, `description is ${m.description.length} chars`);
  assert.deepEqual(m.permissions, ['storage']);
  assert.deepEqual(m.host_permissions, []);
  assert.match(m.content_security_policy.extension_pages, /connect-src 'none'/);
  const schema = JSON.parse(readFileSync(resolve(ROOT, 'extension', m.storage.managed_schema), 'utf8'));
  assert.equal(schema.type, 'object');
});

await test('content script uses a closed shadow root', () => {
  const src = readFileSync(resolve(ROOT, 'extension/content/content.js'), 'utf8');
  assert.match(src, /attachShadow\(\{\s*mode:\s*'closed'\s*\}\)/);
  assert.doesNotMatch(src, /mode:\s*'open'/);
});

await test('redaction never runs on a truncated result in the extension', () => {
  const src = readFileSync(resolve(ROOT, 'extension/content/content.js'), 'utf8');
  for (const id of ['btnRedact', 'btnCopyRedacted']) {
    const handler = src.slice(src.indexOf(`getElementById('${id}').addEventListener`));
    assert.match(handler.slice(0, 200), /canRewrite\(\)/, `${id} handler must check canRewrite()`);
  }
  assert.ok(redact('x', [], {}).text === 'x');
});

/* Detection quality: redaction must not eat the user's own words ---------- */

for (const [prompt, name] of [
  ['Email John Carter about the renewal.', 'John Carter'],
  ['Dear Priya Shah, thanks for the update.', 'Priya Shah'],
  ['Ask Maria Lopez to review the draft.', 'Maria Lopez'],
]) {
  await test(`leading verb/greeting is not part of the name: "${prompt.split(' ')[0]}"`, () => {
    const names = scan(prompt).findings.filter((f) => f.label === 'NAME').map((f) => f.value);
    assert.deepEqual(names, [name]);
  });
}

await test('a lone imperative is not flagged as a name', () => {
  assert.equal(scan('Email the team about Friday.').findings.filter((f) => f.label === 'NAME').length, 0);
});

/* Shipped sources are clean text (no embedded NUL bytes) ------------------ */

await test('no NUL bytes in shipped source files', () => {
  for (const f of ['engine/ner.js', 'extension/vendor/engine.bundle.js', 'extension/content/content.js', 'assets/app.js']) {
    assert.ok(!readFileSync(resolve(ROOT, f)).includes(0), `${f} contains a NUL byte`);
  }
});

/* report ------------------------------------------------------------------ */

let failed = 0;
for (const [ok, name, err] of results) {
  console.log(`${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}`);
  if (!ok) { failed++; console.log(`      ${err.message}`); }
}
console.log(`\nsecurity  ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
