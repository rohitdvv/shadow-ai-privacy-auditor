/**
 * Scan orchestration.
 *
 * scan(text, options) -> {
 *   text, findings[], risk, verdict, stats, policy
 * }
 *
 * The whole pipeline is synchronous, pure and offline. No network calls exist
 * anywhere in this module or its imports — that is a deliberate, testable
 * property of the design, not just a promise in the README.
 */

import { CATEGORY_META, SEVERITY_RANK } from './constants.js';
import { RULES, CONTEXT_WINDOW, STRONG_IDENTIFIER_RULES } from './patterns.js';
import { extractEntities } from './ner.js';
import { computeSafeSpans, isInsideSafeSpan, scoreContext, resolveOverlaps } from './context.js';
import { scoreRisk, verdict } from './risk.js';
import { normalisePolicy, buildCustomRules, DEFAULT_POLICY } from './policy.js';

const MAX_INPUT = 200_000;
const indexedRegexCache = new WeakMap();

function withIndices(regex) {
  let cached = indexedRegexCache.get(regex);
  if (cached) return cached;
  const flags = regex.flags.includes('d') ? regex.flags : regex.flags + 'd';
  cached = new RegExp(regex.source, flags);
  indexedRegexCache.set(regex, cached);
  return cached;
}

let idCounter = 0;
const nextId = () => `f${(++idCounter).toString(36)}`;

/**
 * @param {string} text
 * @param {object} [options]
 * @param {object} [options.policy]      policy object (see policy.js)
 * @param {boolean} [options.ner=true]   run the name/organisation extractor
 * @returns {object} scan result
 */
export function scan(text, options = {}) {
  const started = now();
  const policy = normalisePolicy(options.policy || DEFAULT_POLICY);
  const input = typeof text === 'string' ? text : '';
  const truncated = input.length > MAX_INPUT;
  const body = truncated ? input.slice(0, MAX_INPUT) : input;

  if (!body.trim()) {
    return emptyResult(body, policy, started, truncated);
  }

  const safeSpans = computeSafeSpans(body);
  const enabled = new Set(policy.enabledCategories);
  const allRules = [...RULES, ...buildCustomRules(policy)];
  const candidates = [];

  for (const rule of allRules) {
    if (!enabled.has(rule.category)) continue;
    collectRuleMatches(rule, body, safeSpans, candidates);
  }

  if (options.ner !== false) {
    for (const entity of extractEntities(body)) {
      if (!enabled.has(entity.category)) continue;
      if (isInsideSafeSpan(safeSpans, entity.start, entity.end)) continue;
      candidates.push({
        id: nextId(),
        ...entity,
        method: 'ner',
      });
    }
  }

  // Context scoring
  for (const c of candidates) scoreContext(c, body);

  // Policy severity overrides
  for (const c of candidates) {
    const override = policy.severityOverrides[c.category];
    if (override && SEVERITY_RANK[override] > SEVERITY_RANK[c.severity]) c.severity = override;
  }

  // Threshold + overlap resolution
  const reported = candidates.filter((c) => c.confidence >= policy.reportThreshold);
  const findings = resolveOverlaps(reported).map((f) => ({
    ...f,
    categoryName: CATEGORY_META[f.category]?.name || f.category,
    categoryWhy: CATEGORY_META[f.category]?.why || '',
    redact: f.confidence >= policy.redactThreshold,
    dismissed: false,
    line: lineNumberAt(body, f.start),
  }));

  const risk = scoreRisk(findings);

  return {
    text: body,
    truncated,
    findings,
    risk,
    verdict: verdict(risk, policy),
    policy,
    stats: {
      characters: body.length,
      words: body.trim() ? body.trim().split(/\s+/).length : 0,
      candidates: candidates.length,
      reported: findings.length,
      suppressed: candidates.length - findings.length,
      durationMs: Math.round((now() - started) * 100) / 100,
      rulesEvaluated: allRules.length,
    },
  };
}

function collectRuleMatches(rule, body, safeSpans, out) {
  const re = withIndices(rule.regex);
  re.lastIndex = 0;
  let m;
  let guard = 0;

  while ((m = re.exec(body)) !== null) {
    if (++guard > 5000) break;
    if (m[0].length === 0) { re.lastIndex++; continue; }

    const g = rule.group || 0;
    const span = (m.indices && m.indices[g]) || null;
    if (g > 0 && !span) continue;
    const start = span ? span[0] : m.index;
    const end = span ? span[1] : m.index + m[0].length;
    const value = body.slice(start, end);
    if (!value) continue;

    if (!rule.ignoreSafeSpans && isInsideSafeSpan(safeSpans, start, end)) continue;

    const context = body.slice(
      Math.max(0, m.index - CONTEXT_WINDOW),
      Math.min(body.length, m.index + m[0].length + CONTEXT_WINDOW),
    );

    if (rule.needsContext && !rule.needsContext.test(context)) continue;

    let severity = rule.severity;
    let confidence = rule.confidence;
    let note;
    let label = rule.label;

    if (typeof rule.validate === 'function') {
      const verdictValue = rule.validate(value, { ...m, context }, body);
      if (verdictValue === false || verdictValue === null || verdictValue === undefined) continue;
      if (typeof verdictValue === 'object') {
        if (verdictValue.severity) severity = verdictValue.severity;
        if (typeof verdictValue.confidence === 'number') confidence = verdictValue.confidence;
        if (verdictValue.note) note = verdictValue.note;
        if (verdictValue.label) label = verdictValue.label;
      }
    }

    out.push({
      id: nextId(),
      ruleId: rule.id,
      category: rule.category,
      severity,
      label,
      title: rule.title,
      why: rule.why,
      note,
      value,
      start,
      end,
      confidence,
      method: rule.custom ? 'policy' : 'pattern',
      strongIdentifier: STRONG_IDENTIFIER_RULES.has(rule.id),
      signals: [],
      matchText: m[0],
    });
  }
}

function lineNumberAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

function emptyResult(body, policy, started, truncated) {
  const risk = scoreRisk([]);
  return {
    text: body,
    truncated,
    findings: [],
    risk,
    verdict: verdict(risk, policy),
    policy,
    stats: {
      characters: body.length,
      words: 0,
      candidates: 0,
      reported: 0,
      suppressed: 0,
      durationMs: Math.round((now() - started) * 100) / 100,
      rulesEvaluated: 0,
    },
  };
}

function now() {
  if (typeof performance !== 'undefined' && performance.now) return performance.now();
  return Date.now();
}
