/**
 * Storage helpers shared by the background worker, popup and options page.
 *
 * Two stores:
 *   sync  — the policy, so a user's configuration follows their Chrome profile
 *   local — the content-free audit log, which never syncs anywhere
 */

export const POLICY_KEY = 'policy';
export const ENABLED_KEY = 'enabled';
export const LOG_KEY = 'auditLog';
export const MAX_LOG = 500;

export async function getPolicy() {
  const { [POLICY_KEY]: policy } = await chrome.storage.sync.get(POLICY_KEY);
  return policy || null;
}

export async function setPolicy(policy) {
  await chrome.storage.sync.set({ [POLICY_KEY]: policy });
}

export async function isEnabled() {
  const { [ENABLED_KEY]: enabled } = await chrome.storage.sync.get(ENABLED_KEY);
  return enabled !== false;
}

export async function setEnabled(value) {
  await chrome.storage.sync.set({ [ENABLED_KEY]: !!value });
}

/**
 * Enterprise policy pushed by an administrator through Chrome's managed storage
 * (Google Admin console / Windows GPO / macOS profiles — see managed_schema.json).
 * Read-only for the user, and delivered with zero network calls by the extension.
 */
export async function getManaged() {
  try {
    const { policy = null, forceEnabled = false } = await chrome.storage.managed.get(['policy', 'forceEnabled']);
    return { policy: policy && typeof policy === 'object' ? policy : null, forceEnabled: forceEnabled === true };
  } catch {
    return { policy: null, forceEnabled: false };   // managed storage unavailable (unmanaged browser)
  }
}

/** The config content scripts actually run with: a managed policy always wins. */
export async function getEffectiveConfig() {
  const managed = await getManaged();
  return {
    policy: managed.policy || (await getPolicy()),
    enabled: managed.forceEnabled ? true : await isEnabled(),
    managed: { policy: !!managed.policy, forceEnabled: managed.forceEnabled },
  };
}

/* Audit entries come from content scripts running inside third-party pages, so
   every field is coerced to a known shape before it is stored or rendered. */
const BANDS = new Set(['safe', 'low', 'moderate', 'high', 'critical']);
const ACTIONS = new Set(['scanned', 'redacted', 'sent-anyway', 'sent-clean', 'cancelled', 'blocked']);
const CATEGORY_IDS = new Set(['contact', 'government_financial', 'credentials', 'medical_sensitive', 'people_records', 'org_confidential']);
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const count = (v, max = 100000) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) && n > 0 ? Math.min(n, max) : 0;
};

/**
 * Append an audit entry. Content is never stored — only counts, categories,
 * the risk score, the host and what the user chose to do.
 */
export async function appendAudit(entry = {}) {
  const { [LOG_KEY]: log = [] } = await chrome.storage.local.get(LOG_KEY);
  const byCategory = {};
  for (const [c, n] of Object.entries(entry.byCategory || {})) {
    if (CATEGORY_IDS.has(c)) byCategory[c] = count(n);
  }
  const counts = {};
  for (const s of SEVERITIES) counts[s] = count(entry.counts?.[s]);
  log.unshift({
    at: new Date().toISOString(),
    host: typeof entry.host === 'string' ? entry.host.slice(0, 253) : null,
    score: count(entry.score, 100),
    band: BANDS.has(entry.band) ? entry.band : 'safe',
    counts,
    byCategory,
    totalFindings: count(entry.totalFindings),
    action: ACTIONS.has(entry.action) ? entry.action : 'scanned',
    redactedCount: count(entry.redactedCount),
  });
  await chrome.storage.local.set({ [LOG_KEY]: log.slice(0, MAX_LOG) });
}

export async function readAudit() {
  const { [LOG_KEY]: log = [] } = await chrome.storage.local.get(LOG_KEY);
  return log;
}

export async function clearAudit() {
  await chrome.storage.local.remove(LOG_KEY);
}

export function summarise(log) {
  const out = {
    scans: log.length,
    blocked: 0, redacted: 0, overridden: 0, clean: 0,
    findings: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    byCategory: {},
    byHost: {},
    last7Days: 0,
  };
  const weekAgo = Date.now() - 7 * 24 * 3600 * 1000;
  for (const e of log) {
    if (e.action === 'blocked') out.blocked++;
    if (e.action === 'redacted') out.redacted++;
    if (e.action === 'sent-anyway') out.overridden++;
    if ((e.totalFindings || 0) === 0) out.clean++;
    out.findings += e.totalFindings || 0;
    for (const k of Object.keys(out.bySeverity)) out.bySeverity[k] += e.counts?.[k] || 0;
    for (const [c, n] of Object.entries(e.byCategory || {})) out.byCategory[c] = (out.byCategory[c] || 0) + n;
    if (e.host) out.byHost[e.host] = (out.byHost[e.host] || 0) + 1;
    if (new Date(e.at).getTime() >= weekAgo) out.last7Days++;
  }
  return out;
}

export function toCsv(log) {
  const header = ['timestamp', 'host', 'score', 'band', 'findings', 'critical', 'high', 'medium', 'low', 'action', 'redacted'];
  const cell = (v) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [header, ...log.map((e) => [
    e.at, e.host || '', e.score, e.band, e.totalFindings,
    e.counts?.critical || 0, e.counts?.high || 0, e.counts?.medium || 0, e.counts?.low || 0,
    e.action, e.redactedCount || 0,
  ])].map((r) => r.map(cell).join(',')).join('\n');
}
