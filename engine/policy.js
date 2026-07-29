/**
 * Enterprise policy layer.
 *
 * A policy is a plain JSON object an administrator can ship to every user
 * (via the extension options page or a bundled managed-storage file). It
 * controls which categories are active, thresholds, custom organisational
 * rules and what happens when a critical finding is present.
 */

import { CATEGORIES, SEVERITY } from './constants.js';

export const DEFAULT_POLICY = {
  version: 1,
  name: 'Balanced (default)',
  /** Categories that are scanned at all. */
  enabledCategories: Object.values(CATEGORIES),
  /** Minimum confidence for a finding to be *reported*. */
  reportThreshold: 0.35,
  /** Minimum confidence for a finding to be redacted by default. */
  redactThreshold: 0.5,
  /** Per-category severity overrides, e.g. { org_confidential: 'critical' }. */
  severityOverrides: {},
  /** Placeholder style: 'label' -> [EMAIL], 'numbered' -> [EMAIL_1], 'mask' -> partial mask, 'pseudonym' -> synthetic value. */
  redactionStyle: 'numbered',
  /** Block sending when the risk score reaches this value (extension only). 101 = never block. */
  blockAtScore: 50,
  /** Warn (non-blocking) at this score. */
  warnAtScore: 1,
  /** Organisation-specific literal terms, e.g. internal codenames. */
  customTerms: [],
  /** Organisation-specific regex rules. */
  customRules: [],
  /** Domains treated as internal — emails on these are always flagged. */
  internalDomains: [],
  /** Keep a local, content-free audit trail. */
  auditLog: { enabled: true, storeContent: false, maxEntries: 200 },
};

export const POLICY_PRESETS = {
  balanced: { ...DEFAULT_POLICY },
  strict: {
    ...DEFAULT_POLICY,
    name: 'Strict (regulated environment)',
    reportThreshold: 0.25,
    redactThreshold: 0.35,
    blockAtScore: 25,
    severityOverrides: { [CATEGORIES.ORG]: SEVERITY.CRITICAL, [CATEGORIES.PEOPLE]: SEVERITY.CRITICAL },
  },
  healthcare: {
    ...DEFAULT_POLICY,
    name: 'Healthcare (HIPAA-oriented)',
    reportThreshold: 0.25,
    redactThreshold: 0.4,
    blockAtScore: 25,
    severityOverrides: { [CATEGORIES.MEDICAL]: SEVERITY.CRITICAL, [CATEGORIES.CONTACT]: SEVERITY.CRITICAL },
  },
  finance: {
    ...DEFAULT_POLICY,
    name: 'Financial services (PCI / SOX-oriented)',
    reportThreshold: 0.3,
    redactThreshold: 0.45,
    blockAtScore: 25,
    severityOverrides: { [CATEGORIES.GOV_FIN]: SEVERITY.CRITICAL, [CATEGORIES.ORG]: SEVERITY.CRITICAL },
  },
  engineering: {
    ...DEFAULT_POLICY,
    name: 'Engineering (secret-hunting)',
    reportThreshold: 0.3,
    redactThreshold: 0.45,
    blockAtScore: 40,
    severityOverrides: { [CATEGORIES.CREDENTIALS]: SEVERITY.CRITICAL },
  },
  permissive: {
    ...DEFAULT_POLICY,
    name: 'Permissive (high precision only)',
    reportThreshold: 0.55,
    redactThreshold: 0.7,
    blockAtScore: 101,
  },
};

export function normalisePolicy(input) {
  const p = { ...DEFAULT_POLICY, ...(input || {}) };
  p.enabledCategories = Array.isArray(p.enabledCategories) && p.enabledCategories.length
    ? p.enabledCategories.filter((c) => Object.values(CATEGORIES).includes(c))
    : [...DEFAULT_POLICY.enabledCategories];
  p.reportThreshold = clamp(p.reportThreshold, 0, 1);
  p.redactThreshold = clamp(Math.max(p.redactThreshold, p.reportThreshold), 0, 1);
  p.customTerms = (p.customTerms || []).filter((t) => typeof t === 'string' && t.trim().length >= 3);
  p.customRules = (p.customRules || []).filter((r) => r && r.pattern);
  p.internalDomains = (p.internalDomains || []).map((d) => String(d).toLowerCase().replace(/^@/, ''));
  p.auditLog = { ...DEFAULT_POLICY.auditLog, ...(p.auditLog || {}) };
  return p;
}

function clamp(n, lo, hi) {
  const v = Number(n);
  if (Number.isNaN(v)) return lo;
  return Math.min(hi, Math.max(lo, v));
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Turn policy custom terms and custom regexes into engine rules.
 */
export function buildCustomRules(policy) {
  const rules = [];

  if (policy.customTerms.length) {
    rules.push({
      id: 'policy_custom_term',
      category: CATEGORIES.ORG,
      severity: SEVERITY.HIGH,
      label: 'INTERNAL_TERM',
      title: 'Organisation-defined restricted term',
      why: 'Your organisation has listed this term as restricted. Mentioning it externally may confirm work that has not been announced.',
      confidence: 0.9,
      group: 0,
      regex: new RegExp(`\\b(?:${policy.customTerms.map(escapeRe).sort((a, b) => b.length - a.length).join('|')})\\b`, 'gi'),
      custom: true,
    });
  }

  for (const [i, r] of policy.customRules.entries()) {
    let regex;
    try {
      regex = new RegExp(r.pattern, r.flags && /^[gimsuy]*$/.test(r.flags) ? ensureGlobal(r.flags) : 'gi');
    } catch {
      continue; // an invalid admin regex must never break scanning
    }
    rules.push({
      id: r.id || `policy_custom_rule_${i}`,
      category: Object.values(CATEGORIES).includes(r.category) ? r.category : CATEGORIES.ORG,
      severity: Object.values(SEVERITY).includes(r.severity) ? r.severity : SEVERITY.HIGH,
      label: (r.label || 'CUSTOM').toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
      title: r.title || 'Custom policy rule',
      why: r.why || 'Flagged by a rule configured by your organisation.',
      confidence: typeof r.confidence === 'number' ? clamp(r.confidence, 0, 1) : 0.85,
      group: Number.isInteger(r.group) ? r.group : 0,
      regex,
      custom: true,
    });
  }

  if (policy.internalDomains.length) {
    rules.push({
      id: 'policy_internal_email_domain',
      category: CATEGORIES.PEOPLE,
      severity: SEVERITY.HIGH,
      label: 'INTERNAL_EMAIL',
      title: 'Internal email address',
      why: 'This mailbox belongs to your organisation. Exposing internal addresses enables targeted phishing against your colleagues.',
      confidence: 0.95,
      group: 0,
      regex: new RegExp(`\\b[A-Za-z0-9._%+-]+@(?:${policy.internalDomains.map(escapeRe).join('|')})\\b`, 'gi'),
      custom: true,
    });
  }

  return rules;
}

function ensureGlobal(flags) {
  return flags.includes('g') ? flags : flags + 'g';
}
