/**
 * Severity & risk scoring.
 *
 * The score answers one question: "how bad would it be if this exact text
 * left my machine?" It is deliberately dominated by the worst single finding
 * rather than by volume, so ten low-risk names never outrank one live API key.
 */

import { SEVERITY_WEIGHT, SEVERITY_RANK, CATEGORY_META, bandForScore } from './constants.js';

export function scoreRisk(findings) {
  const active = findings.filter((f) => !f.dismissed);
  if (!active.length) {
    return {
      score: 0,
      band: bandForScore(0),
      worstSeverity: null,
      counts: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategory: {},
      total: 0,
      uniqueValues: 0,
      rationale: ['No sensitive information detected.'],
    };
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory = {};
  const seen = new Map();          // dedupe identical values
  let raw = 0;

  for (const f of active) {
    counts[f.severity]++;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;

    const key = `${f.category}:${String(f.value).trim().toLowerCase()}`;
    const repeats = seen.get(key) || 0;
    seen.set(key, repeats + 1);

    // Repeated occurrences of the same value add little extra risk.
    const decay = 1 / (1 + repeats * 1.6);
    raw += SEVERITY_WEIGHT[f.severity] * f.confidence * decay;
  }

  // Worst-single-finding floor: one confident critical is always >= 75.
  const worst = active.reduce((a, b) => (SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a));
  const floors = { critical: 75, high: 45, medium: 18, low: 5 };
  const floorScale = worst.confidence >= 0.8 ? 1 : Math.max(0.5, worst.confidence);
  const floor = Math.round(floors[worst.severity] * floorScale);

  const score = Math.max(floor, Math.min(100, Math.round(raw)));
  const band = bandForScore(score);

  const rationale = [];
  if (counts.critical) rationale.push(`${counts.critical} critical finding${counts.critical > 1 ? 's' : ''} (identity, financial or credential data).`);
  if (counts.high) rationale.push(`${counts.high} high-severity finding${counts.high > 1 ? 's' : ''}.`);
  if (counts.medium) rationale.push(`${counts.medium} medium-severity finding${counts.medium > 1 ? 's' : ''}.`);
  if (counts.low) rationale.push(`${counts.low} low-severity finding${counts.low > 1 ? 's' : ''}.`);
  const cats = Object.keys(byCategory).map((c) => CATEGORY_META[c]?.short || c);
  if (cats.length) rationale.push(`Categories present: ${cats.join(', ')}.`);

  return {
    score,
    band,
    worstSeverity: worst.severity,
    counts,
    byCategory,
    total: active.length,
    uniqueValues: seen.size,
    rationale,
  };
}

/** Short, plain-language verdict for the top of the UI. */
export function verdict(risk, policy) {
  if (risk.score === 0) {
    return {
      headline: 'Nothing sensitive detected',
      detail: 'This text looks safe to send. Nothing was changed.',
      action: 'send',
    };
  }
  if (policy && risk.score >= policy.blockAtScore) {
    return {
      headline: 'Do not send as written',
      detail: 'This prompt contains information your policy blocks from leaving the organisation. Redact before sending.',
      action: 'block',
    };
  }
  return {
    headline: 'Review before sending',
    detail: 'Some details in this prompt identify people or your organisation. Redact what is not needed for the answer.',
    action: 'warn',
  };
}
