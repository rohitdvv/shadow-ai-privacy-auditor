/**
 * Shadow AI Privacy Auditor — public engine API.
 *
 * Everything here runs locally. There is no fetch/XHR/WebSocket anywhere in
 * the engine; `npm run verify:offline` asserts that in CI.
 */

export { scan } from './engine.js';
export { redact, segment } from './redact.js';
export { scoreRisk, verdict } from './risk.js';
export {
  CATEGORIES, CATEGORY_META, CATEGORY_LIST, SEVERITY, SEVERITY_RANK,
  SEVERITY_WEIGHT, RISK_BANDS, bandForScore,
} from './constants.js';
export { DEFAULT_POLICY, POLICY_PRESETS, normalisePolicy } from './policy.js';
export { RULES, RULES_BY_ID } from './patterns.js';
export { extractEntities } from './ner.js';
export { recordScan, readLog, clearLog, summariseLog, exportLogCsv } from './audit.js';

export const ENGINE_VERSION = '1.0.0';

/** Convenience: scan then redact in one call. */
export async function audit(text, options = {}) {
  const { scan } = await import('./engine.js');
  const { redact } = await import('./redact.js');
  const result = scan(text, options);
  const redaction = redact(result.text, result.findings, { style: result.policy.redactionStyle });
  return { ...result, redaction };
}
