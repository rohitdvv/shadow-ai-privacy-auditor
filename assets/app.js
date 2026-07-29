/**
 * Shadow AI Privacy Auditor — web app controller.
 *
 * Imports the same engine module the browser extension uses, so the web demo
 * and the extension can never disagree about what is sensitive.
 */

import {
  scan, redact, segment,
  CATEGORY_META, CATEGORY_LIST, CATEGORIES,
  DEFAULT_POLICY, POLICY_PRESETS, normalisePolicy,
  recordScan, readLog, clearLog, summariseLog, exportLogCsv,
} from '../engine/index.js';
import { CASES } from '../tests/cases.js';

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

const POLICY_KEY = 'shadow-ai-auditor:policy:v1';
const THEME_KEY = 'shadow-ai-auditor:theme';

const state = {
  policy: loadPolicy(),
  result: null,
  redaction: null,
  activeId: null,
  style: 'numbered',
};

const $ = (sel) => document.querySelector(sel);
const el = {
  editor: $('#editor'), charCount: $('#charCount'), scanTime: $('#scanTime'),
  highlightBox: $('#highlightBox'), legend: $('#legend'),
  verdict: $('#verdict'), gaugeFill: $('#gaugeFill'), scoreValue: $('#scoreValue'),
  headline: $('.verdict-headline'), detail: $('#verdictDetail'), chips: $('#severityChips'),
  findings: $('#findings'), findingCount: $('#findingCount'),
  output: $('#output'), redactionSummary: $('#redactionSummary'),
  sampleSelect: $('#sampleSelect'), styleSelect: $('#styleSelect'),
  toast: $('#toast'), scrim: $('#scrim'),
};

/* ------------------------------------------------------------------ */
/* scanning                                                            */
/* ------------------------------------------------------------------ */

let debounceTimer = null;
function scheduleScan() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => render(scanNow(el.editor.value)), 160);
}

function scanNow(text) {
  const result = scan(text, { policy: state.policy });
  state.result = result;
  return result;
}

function recompute() {
  if (!state.result) return;
  state.redaction = redact(state.result.text, state.result.findings, { style: state.style });
  renderOutput();
  renderHighlights();
  renderFindings();
  renderVerdict();
}

/* ------------------------------------------------------------------ */
/* render                                                              */
/* ------------------------------------------------------------------ */

function render(result) {
  el.charCount.textContent = `${result.stats.characters.toLocaleString()} characters · ${result.stats.words.toLocaleString()} words`;
  el.scanTime.textContent = result.stats.characters
    ? `scanned locally in ${result.stats.durationMs} ms · ${result.stats.rulesEvaluated} rules`
    : '';
  recompute();
  if (result.findings.length) {
    recordScan(result, { source: 'web', action: 'scanned' });
    refreshAudit();
  }
}

function renderVerdict() {
  const { risk, verdict } = state.result;
  const band = risk.band;
  el.verdict.style.setProperty('--band-color', band.color);
  el.verdict.dataset.band = band.level;
  el.scoreValue.textContent = risk.score;

  const circumference = 2 * Math.PI * 50;
  el.gaugeFill.style.strokeDashoffset = String(circumference * (1 - risk.score / 100));

  const hasText = state.result.stats.characters > 0;
  el.headline.textContent = hasText ? verdict.headline : 'Paste something to get started';
  el.detail.textContent = hasText
    ? `${verdict.detail} ${risk.rationale.join(' ')}`.trim()
    : 'The auditor will tell you what is risky, why it matters, and give you a safe version to send instead.';

  el.chips.innerHTML = '';
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const n = risk.counts[sev];
    if (!n) continue;
    const li = document.createElement('li');
    li.className = 'chip';
    li.dataset.sev = sev;
    li.textContent = `${n} ${sev}`;
    el.chips.append(li);
  }
}

function renderHighlights() {
  const { text, findings } = state.result;
  if (!text.trim()) {
    el.highlightBox.innerHTML = '<p class="empty">Highlighted text will appear here once you type or paste something.</p>';
    return;
  }
  const frag = document.createDocumentFragment();
  for (const seg of segment(text, findings)) {
    if (!seg.finding) {
      frag.append(document.createTextNode(seg.text));
      continue;
    }
    const meta = CATEGORY_META[seg.finding.category];
    const mark = document.createElement('mark');
    mark.className = `hit${seg.finding.redact ? '' : ' is-kept'}${seg.finding.id === state.activeId ? ' is-active' : ''}`;
    mark.style.setProperty('--hit-color', meta.color);
    mark.style.setProperty('--hit-tint', meta.tint);
    mark.dataset.id = seg.finding.id;
    mark.dataset.severity = seg.finding.severity;
    mark.tabIndex = 0;
    mark.title = `${meta.short} · ${seg.finding.title} · ${seg.finding.severity}`;
    mark.textContent = seg.text;
    frag.append(mark);
  }
  el.highlightBox.replaceChildren(frag);
}

function renderFindings() {
  const { findings } = state.result;
  el.findingCount.textContent = findings.length;

  if (!findings.length) {
    el.findings.innerHTML = state.result.stats.characters
      ? '<p class="empty">Nothing sensitive found. This text is safe to send as written.</p>'
      : '<p class="empty">No findings yet.</p>';
    return;
  }

  const groups = new Map();
  for (const f of findings) {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }

  const frag = document.createDocumentFragment();
  for (const cat of CATEGORY_LIST) {
    const list = groups.get(cat.id);
    if (!list) continue;

    const group = document.createElement('div');
    group.className = 'cat-group';

    const head = document.createElement('div');
    head.className = 'cat-head';
    head.style.setProperty('--cat-tint', cat.tint);
    head.innerHTML = `<span>${escapeHtml(cat.name)}</span><span class="cat-count">${list.length}</span>`;
    group.append(head);

    for (const f of list) group.append(findingRow(f, cat));
    frag.append(group);
  }
  el.findings.replaceChildren(frag);
}

function findingRow(f, cat) {
  const row = document.createElement('div');
  row.className = `finding${f.redact ? '' : ' is-kept'}`;
  row.dataset.id = f.id;

  const main = document.createElement('div');
  main.className = 'finding-main';

  const value = document.createElement('code');
  value.className = 'finding-value';
  value.textContent = truncate(f.value.replace(/\n/g, ' ⏎ '), 72);
  main.append(value);

  const title = document.createElement('p');
  title.className = 'finding-title';
  title.textContent = f.title + (f.note ? ` — ${f.note}` : '');
  main.append(title);

  const why = document.createElement('p');
  why.className = 'finding-why';
  why.textContent = f.why;
  main.append(why);

  const meta = document.createElement('div');
  meta.className = 'finding-meta';
  meta.append(chip(f.severity));
  meta.append(tag(`confidence ${(f.confidence * 100).toFixed(0)}%`));
  meta.append(tag(f.method === 'ner' ? 'name recogniser' : f.method === 'policy' ? 'org policy' : 'pattern + validator'));
  meta.append(tag(`line ${f.line}`));
  main.append(meta);

  if (f.signals?.length) {
    const more = document.createElement('details');
    more.className = 'why-more';
    more.innerHTML = `<summary>Why this was flagged</summary><p>${escapeHtml(f.signals.join(' · '))}</p>`;
    main.append(more);
  }

  const actions = document.createElement('div');
  actions.className = 'finding-actions';

  const toggle = document.createElement('button');
  toggle.className = 'btn small';
  toggle.textContent = f.redact ? 'Keep' : 'Redact';
  toggle.title = f.redact ? 'Leave this text as it is' : 'Replace this with a placeholder';
  toggle.addEventListener('click', () => {
    f.redact = !f.redact;
    recompute();
  });
  actions.append(toggle);

  const locate = document.createElement('button');
  locate.className = 'btn ghost small';
  locate.textContent = 'Show';
  locate.addEventListener('click', () => {
    state.activeId = f.id;
    renderHighlights();
    el.highlightBox.querySelector(`[data-id="${f.id}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  });
  actions.append(locate);

  row.append(main, actions);
  return row;
}

function renderOutput() {
  const r = state.redaction;
  if (!state.result.stats.characters) {
    el.output.innerHTML = '<span class="empty">The redacted version will appear here.</span>';
    el.redactionSummary.textContent = '';
    return;
  }
  const text = r.text;
  // Highlight the placeholders so the change is obvious.
  const html = escapeHtml(text).replace(/\[([A-Z_]+(?:_\d+)?)\]/g, '<span class="ph">[$1]</span>');
  el.output.innerHTML = html || '<span class="empty">(empty)</span>';

  if (!r.changed) {
    el.redactionSummary.textContent = 'Nothing was changed — this text is safe to send exactly as written.';
  } else {
    const labels = [...new Set(r.replacements.map((x) => x.label))].join(', ');
    el.redactionSummary.textContent = `${r.replacements.length} replacement${r.replacements.length > 1 ? 's' : ''} made (${labels}). Everything else is byte-for-byte unchanged.`;
  }
}

function chip(severity) {
  const s = document.createElement('span');
  s.className = 'chip';
  s.dataset.sev = severity;
  s.textContent = severity;
  return s;
}

function tag(label) {
  const s = document.createElement('span');
  s.className = 'meta-tag';
  s.textContent = label;
  return s;
}

/* ------------------------------------------------------------------ */
/* legend, samples                                                      */
/* ------------------------------------------------------------------ */

function buildLegend() {
  el.legend.replaceChildren(...CATEGORY_LIST.map((c) => {
    const s = document.createElement('span');
    s.className = 'legend-item';
    s.title = c.description;
    s.innerHTML = `<span class="legend-swatch" style="background:${c.color}"></span>${escapeHtml(c.short)}`;
    return s;
  }));
}

const SAMPLE_IDS = ['S-01', 'S-04', 'S-06', 'R-01', 'R-05', 'R-10', 'R-13', 'R-16', 'R-19', 'E-01', 'E-05'];

function buildSamples() {
  for (const id of SAMPLE_IDS) {
    const tc = CASES.find((c) => c.id === id);
    if (!tc) continue;
    const opt = document.createElement('option');
    opt.value = id;
    opt.textContent = `${tc.kind === 'safe' ? '✅' : tc.kind === 'edge' ? '⚖️' : '⚠️'}  ${tc.name}`;
    el.sampleSelect.append(opt);
  }
}

/* ------------------------------------------------------------------ */
/* policy panel                                                         */
/* ------------------------------------------------------------------ */

function buildPolicyPanel() {
  const presetSelect = $('#presetSelect');
  presetSelect.replaceChildren(...Object.entries(POLICY_PRESETS).map(([key, p]) => {
    const o = document.createElement('option');
    o.value = key; o.textContent = p.name;
    return o;
  }));

  $('#categoryToggles').replaceChildren(...CATEGORY_LIST.map((c) => {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" value="${c.id}"> <span>${escapeHtml(c.name)}</span>`;
    return label;
  }));

  syncPolicyPanel();
}

function syncPolicyPanel() {
  const p = state.policy;
  for (const box of document.querySelectorAll('#categoryToggles input')) {
    box.checked = p.enabledCategories.includes(box.value);
  }
  setRange('#reportThreshold', '#reportOut', p.reportThreshold, (v) => v.toFixed(2));
  setRange('#redactThreshold', '#redactOut', p.redactThreshold, (v) => v.toFixed(2));
  setRange('#blockAtScore', '#blockOut', p.blockAtScore, (v) => (v > 100 ? 'never' : String(v)));
  $('#customTerms').value = p.customTerms.join('\n');
  $('#internalDomains').value = p.internalDomains.join('\n');
  $('#customRules').value = p.customRules.length ? JSON.stringify(p.customRules, null, 2) : '';
}

function setRange(inputSel, outSel, value, fmt) {
  const input = $(inputSel);
  input.value = value;
  $(outSel).textContent = fmt(Number(value));
  input.oninput = () => { $(outSel).textContent = fmt(Number(input.value)); };
}

function readPolicyPanel() {
  const enabled = [...document.querySelectorAll('#categoryToggles input:checked')].map((b) => b.value);
  let customRules = [];
  const raw = $('#customRules').value.trim();
  const status = $('#customRulesStatus');
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      customRules = Array.isArray(parsed) ? parsed : [parsed];
      status.textContent = `${customRules.length} custom rule(s) loaded.`;
      status.style.color = '';
    } catch (e) {
      status.textContent = `Could not parse JSON: ${e.message}`;
      status.style.color = 'var(--danger)';
    }
  } else {
    status.textContent = '';
  }

  return normalisePolicy({
    ...state.policy,
    enabledCategories: enabled.length ? enabled : Object.values(CATEGORIES),
    reportThreshold: Number($('#reportThreshold').value),
    redactThreshold: Number($('#redactThreshold').value),
    blockAtScore: Number($('#blockAtScore').value),
    customTerms: splitLines($('#customTerms').value),
    internalDomains: splitLines($('#internalDomains').value),
    customRules,
  });
}

const splitLines = (s) => s.split('\n').map((x) => x.trim()).filter(Boolean);

function loadPolicy() {
  try {
    const raw = localStorage.getItem(POLICY_KEY);
    if (raw) return normalisePolicy(JSON.parse(raw));
  } catch { /* fall through to default */ }
  return normalisePolicy(DEFAULT_POLICY);
}

function savePolicy() {
  try { localStorage.setItem(POLICY_KEY, JSON.stringify(state.policy)); } catch { /* storage blocked */ }
}

/* ------------------------------------------------------------------ */
/* audit panel                                                          */
/* ------------------------------------------------------------------ */

function refreshAudit() {
  const log = readLog();
  const s = summariseLog(log);
  $('#auditSummary').innerHTML = `
    <div class="audit-stat"><strong>${s.scans}</strong><span>prompts checked</span></div>
    <div class="audit-stat"><strong>${s.findings}</strong><span>items detected</span></div>
    <div class="audit-stat"><strong>${s.bySeverity.critical}</strong><span>critical items caught</span></div>
    <div class="audit-stat"><strong>${s.sentClean}</strong><span>prompts that were already clean</span></div>`;

  $('#auditList').replaceChildren(...log.slice(0, 25).map((e) => {
    const row = document.createElement('div');
    row.className = 'audit-row';
    row.innerHTML = `<span>${new Date(e.at).toLocaleString()}</span><span>score ${e.score} · ${e.totalFindings} item(s)</span>`;
    return row;
  }));
}

/* ------------------------------------------------------------------ */
/* events                                                              */
/* ------------------------------------------------------------------ */

function wireEvents() {
  el.editor.addEventListener('input', scheduleScan);
  el.editor.addEventListener('paste', () => setTimeout(scheduleScan, 0));

  $('#btnClear').addEventListener('click', () => {
    el.editor.value = '';
    state.activeId = null;
    render(scanNow(''));
    el.editor.focus();
  });

  el.sampleSelect.addEventListener('change', (e) => {
    const tc = CASES.find((c) => c.id === e.target.value);
    if (!tc) return;
    el.editor.value = tc.text;
    render(scanNow(tc.text));
    e.target.value = '';
  });

  el.styleSelect.addEventListener('change', (e) => {
    state.style = e.target.value;
    recompute();
  });

  $('#btnRedactAll').addEventListener('click', () => {
    state.result.findings.forEach((f) => { f.redact = true; });
    recompute();
  });
  $('#btnKeepAll').addEventListener('click', () => {
    state.result.findings.forEach((f) => { f.redact = false; });
    recompute();
  });

  $('#btnCopy').addEventListener('click', async () => {
    const text = state.redaction?.text ?? '';
    if (!text) return toast('Nothing to copy yet');
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.append(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    recordScan(state.result, {
      source: 'web', action: state.redaction.changed ? 'redacted' : 'sent-clean',
      redactedCount: state.redaction.replacements.length,
    });
    refreshAudit();
    toast(state.redaction.changed
      ? `Copied — ${state.redaction.replacements.length} item(s) redacted`
      : 'Copied — nothing needed redacting');
  });

  el.highlightBox.addEventListener('click', (e) => {
    const mark = e.target.closest('mark.hit');
    if (!mark) return;
    state.activeId = mark.dataset.id;
    renderHighlights();
    el.findings.querySelector(`[data-id="${mark.dataset.id}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  });

  // drawers
  $('#btnPolicy').addEventListener('click', () => openDrawer('#policyPanel', '#btnPolicy'));
  $('#btnAudit').addEventListener('click', () => { refreshAudit(); openDrawer('#auditPanel', '#btnAudit'); });
  for (const b of document.querySelectorAll('[data-close-drawer]')) b.addEventListener('click', closeDrawers);
  el.scrim.addEventListener('click', closeDrawers);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawers(); });

  $('#presetSelect').addEventListener('change', (e) => {
    state.policy = normalisePolicy(POLICY_PRESETS[e.target.value] || DEFAULT_POLICY);
    syncPolicyPanel();
    savePolicy();
    render(scanNow(el.editor.value));
    toast(`Applied preset: ${state.policy.name}`);
  });

  $('#btnApplyPolicy').addEventListener('click', () => {
    state.policy = readPolicyPanel();
    savePolicy();
    render(scanNow(el.editor.value));
    toast('Policy applied');
  });

  $('#btnResetPolicy').addEventListener('click', () => {
    state.policy = normalisePolicy(DEFAULT_POLICY);
    syncPolicyPanel();
    savePolicy();
    render(scanNow(el.editor.value));
    toast('Policy reset to defaults');
  });

  $('#btnExportPolicy').addEventListener('click', () => {
    download('shadow-ai-policy.json', JSON.stringify(state.policy, null, 2), 'application/json');
  });

  $('#btnExportAudit').addEventListener('click', () => {
    download('shadow-ai-activity.csv', exportLogCsv(), 'text/csv');
  });

  $('#btnClearAudit').addEventListener('click', () => {
    clearLog();
    refreshAudit();
    toast('Local activity log cleared');
  });

  $('#btnTheme').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
  });

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      $('#btnCopy').click();
    }
  });
}

function openDrawer(sel, buttonSel) {
  closeDrawers();
  $(sel).hidden = false;
  el.scrim.hidden = false;
  $(buttonSel).setAttribute('aria-expanded', 'true');
  $(sel).querySelector('button, select, input, textarea')?.focus();
}

function closeDrawers() {
  for (const d of document.querySelectorAll('.drawer')) d.hidden = true;
  el.scrim.hidden = true;
  $('#btnPolicy').setAttribute('aria-expanded', 'false');
  $('#btnAudit').setAttribute('aria-expanded', 'false');
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function initTheme() {
  let theme = null;
  try { theme = localStorage.getItem(THEME_KEY); } catch { /* ignore */ }
  if (!theme) theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
}

let toastTimer = null;
function toast(message) {
  el.toast.textContent = message;
  el.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.toast.hidden = true; }, 2600);
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function truncate(s, n) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/* ------------------------------------------------------------------ */
/* boot — last, so every module-level const above is initialised        */
/* ------------------------------------------------------------------ */

initTheme();
buildLegend();
buildSamples();
buildPolicyPanel();
wireEvents();
render(scanNow(''));
