/**
 * Content-free local audit log.
 *
 * PRIVACY DESIGN NOTE — this is the important part:
 * the audit log stores *counts and categories only*. It never stores the
 * scanned text, never stores a detected value, and never leaves the device.
 * An organisation gets the compliance signal ("shadow-AI usage is being
 * checked, 12 credential leaks were prevented this month") without building a
 * secondary database of exactly the secrets it was trying to protect.
 */

const KEY = 'shadow-ai-auditor:audit-log:v1';

function safeStorage() {
  try {
    if (typeof localStorage !== 'undefined') return localStorage;
  } catch { /* blocked by browser settings */ }
  return null;
}

export function recordScan(result, meta = {}) {
  const policy = result.policy || {};
  if (!policy.auditLog || policy.auditLog.enabled === false) return null;

  const entry = {
    at: new Date().toISOString(),
    source: meta.source || 'web',
    host: meta.host || null,
    score: result.risk.score,
    band: result.risk.band.level,
    counts: result.risk.counts,
    byCategory: result.risk.byCategory,
    totalFindings: result.findings.length,
    charCount: result.stats.characters,
    action: meta.action || null,
    redactedCount: meta.redactedCount ?? null,
  };

  // Opt-in only, and off by default. Kept for debugging in permissive setups.
  if (policy.auditLog.storeContent) entry.sample = String(result.text).slice(0, 240);

  const store = safeStorage();
  if (!store) return entry;

  try {
    const log = readLog();
    log.unshift(entry);
    const max = policy.auditLog.maxEntries || 200;
    store.setItem(KEY, JSON.stringify(log.slice(0, max)));
  } catch { /* quota or serialization issue — auditing must never break scanning */ }

  return entry;
}

export function readLog() {
  const store = safeStorage();
  if (!store) return [];
  try {
    const raw = store.getItem(KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function clearLog() {
  const store = safeStorage();
  if (store) {
    try { store.removeItem(KEY); } catch { /* ignore */ }
  }
}

export function summariseLog(log = readLog()) {
  const summary = {
    scans: log.length,
    blocked: log.filter((e) => e.action === 'blocked').length,
    redacted: log.filter((e) => e.action === 'redacted').length,
    sentClean: log.filter((e) => e.score === 0).length,
    findings: log.reduce((n, e) => n + (e.totalFindings || 0), 0),
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    byCategory: {},
    firstAt: log.length ? log[log.length - 1].at : null,
    lastAt: log.length ? log[0].at : null,
  };
  for (const e of log) {
    for (const k of Object.keys(summary.bySeverity)) summary.bySeverity[k] += e.counts?.[k] || 0;
    for (const [cat, n] of Object.entries(e.byCategory || {})) {
      summary.byCategory[cat] = (summary.byCategory[cat] || 0) + n;
    }
  }
  return summary;
}

export function exportLogCsv(log = readLog()) {
  const header = ['timestamp', 'source', 'host', 'score', 'band', 'findings', 'critical', 'high', 'medium', 'low', 'action'];
  const rows = log.map((e) => [
    e.at, e.source, e.host || '', e.score, e.band, e.totalFindings,
    e.counts?.critical || 0, e.counts?.high || 0, e.counts?.medium || 0, e.counts?.low || 0,
    e.action || '',
  ]);
  return [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\n');
}

function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
