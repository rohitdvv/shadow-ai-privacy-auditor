/* global ShadowAI */
/**
 * Options page — policy editor, live tester and local activity view.
 * `ShadowAI` comes from the bundled engine loaded as a classic script.
 */

import { getPolicy, setPolicy, readAudit, clearAudit, summarise, toCsv, getManaged } from '../shared/storage.js';

const $ = (s) => document.querySelector(s);
const { CATEGORY_LIST, POLICY_PRESETS, DEFAULT_POLICY, normalisePolicy, scan, redact, CATEGORY_META } = ShadowAI;

let policy = normalisePolicy(DEFAULT_POLICY);

/* ------------------------------------------------------------------ */

init();

async function init() {
  if (new URLSearchParams(location.search).get('welcome')) $('#welcome').hidden = false;

  const managed = await getManaged();
  $('#managedNotice').hidden = !managed.policy;
  policy = normalisePolicy(managed.policy || (await getPolicy()) || DEFAULT_POLICY);

  buildPresets();
  buildCategories();
  syncForm();
  wire();
  renderAudit();
  runTester();
}

/* ------------------------------------------------------------------ */

function buildPresets() {
  $('#presets').replaceChildren(...Object.entries(POLICY_PRESETS).map(([key, preset]) => {
    const b = document.createElement('button');
    b.className = 'preset';
    b.type = 'button';
    b.dataset.preset = key;
    b.setAttribute('aria-pressed', String(preset.name === policy.name));
    b.innerHTML = `<strong>${escapeHtml(preset.name)}</strong><span>${describePreset(preset)}</span>`;
    b.addEventListener('click', () => {
      policy = normalisePolicy(POLICY_PRESETS[key]);
      syncForm();
      for (const other of document.querySelectorAll('.preset')) {
        other.setAttribute('aria-pressed', String(other.dataset.preset === key));
      }
      runTester();
    });
    return b;
  }));
}

function describePreset(p) {
  const block = p.blockAtScore > 100 ? 'never interrupts' : `interrupts at ${p.blockAtScore}`;
  return `report ≥ ${p.reportThreshold.toFixed(2)} · ${block}`;
}

function buildCategories() {
  $('#categories').replaceChildren(...CATEGORY_LIST.map((c) => {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" value="${c.id}">
      <span><b>${escapeHtml(c.name)}</b><small>${escapeHtml(c.description)}</small></span>`;
    return label;
  }));
}

function syncForm() {
  for (const box of document.querySelectorAll('#categories input')) {
    box.checked = policy.enabledCategories.includes(box.value);
  }
  bindRange('#reportThreshold', '#reportOut', policy.reportThreshold, (v) => v.toFixed(2));
  bindRange('#redactThreshold', '#redactOut', policy.redactThreshold, (v) => v.toFixed(2));
  bindRange('#blockAtScore', '#blockOut', policy.blockAtScore, (v) => (v > 100 ? 'never' : String(v)));
  $('#redactionStyle').value = policy.redactionStyle;
  $('#customTerms').value = policy.customTerms.join('\n');
  $('#internalDomains').value = policy.internalDomains.join('\n');
  $('#customRules').value = policy.customRules.length ? JSON.stringify(policy.customRules, null, 2) : '';
}

function bindRange(inputSel, outSel, value, fmt) {
  const input = $(inputSel);
  input.value = value;
  $(outSel).textContent = fmt(Number(value));
  input.oninput = () => { $(outSel).textContent = fmt(Number(input.value)); runTester(); };
}

function readForm() {
  const enabled = [...document.querySelectorAll('#categories input:checked')].map((b) => b.value);
  let customRules = [];
  const raw = $('#customRules').value.trim();
  const status = $('#rulesStatus');
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      customRules = Array.isArray(parsed) ? parsed : [parsed];
      // Tell the admin which rules the engine will refuse, instead of dropping them silently.
      const rejected = customRules
        .map((r, i) => [i + 1, ShadowAI.checkPatternSafety(r?.pattern)])
        .filter(([, reason]) => reason);
      if (rejected.length) {
        status.textContent = `${customRules.length - rejected.length} rule(s) OK · rejected: `
          + rejected.map(([i, reason]) => `#${i} (${reason})`).join(', ');
        status.style.color = 'var(--danger)';
      } else {
        status.textContent = `${customRules.length} custom rule(s) parsed.`;
        status.style.color = '';
      }
    } catch (err) {
      status.textContent = `Invalid JSON — ${err.message}`;
      status.style.color = 'var(--danger)';
    }
  } else {
    status.textContent = '';
  }

  return normalisePolicy({
    ...policy,
    enabledCategories: enabled,
    reportThreshold: Number($('#reportThreshold').value),
    redactThreshold: Number($('#redactThreshold').value),
    blockAtScore: Number($('#blockAtScore').value),
    redactionStyle: $('#redactionStyle').value,
    customTerms: lines($('#customTerms').value),
    internalDomains: lines($('#internalDomains').value),
    customRules,
  });
}

const lines = (s) => s.split('\n').map((x) => x.trim()).filter(Boolean);

/* ------------------------------------------------------------------ */

function wire() {
  for (const sel of ['#categories', '#redactionStyle', '#customTerms', '#internalDomains', '#customRules']) {
    $(sel).addEventListener('input', () => { policy = readForm(); runTester(); });
    $(sel).addEventListener('change', () => { policy = readForm(); runTester(); });
  }

  $('#tester').addEventListener('input', runTester);

  $('#btnSave').addEventListener('click', async () => {
    policy = readForm();
    await setPolicy(policy);
    flash('Policy saved and pushed to every tab.');
  });

  $('#btnExportPolicy').addEventListener('click', () => {
    download('shadow-ai-policy.json', JSON.stringify(readForm(), null, 2), 'application/json');
  });

  $('#btnImportPolicy').addEventListener('click', () => $('#fileInput').click());

  $('#fileInput').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      policy = normalisePolicy(JSON.parse(await file.text()));
      syncForm();
      runTester();
      flash('Policy imported — press Save to apply it.');
    } catch (err) {
      flash(`Could not read that file: ${err.message}`);
    }
    e.target.value = '';
  });

  $('#btnExportAudit').addEventListener('click', async () => {
    download('shadow-ai-activity.csv', toCsv(await readAudit()), 'text/csv');
  });

  $('#btnClearAudit').addEventListener('click', async () => {
    await clearAudit();
    renderAudit();
    flash('Local activity log cleared.');
  });
}

function flash(message) {
  const node = $('#saveStatus');
  node.textContent = message;
  setTimeout(() => { if (node.textContent === message) node.textContent = ''; }, 4000);
}

/* ------------------------------------------------------------------ */

function runTester() {
  const text = $('#tester').value;
  const out = $('#testerResult');
  if (!text.trim()) { out.replaceChildren(); return; }

  const result = scan(text, { policy: readFormSafe() });
  const redaction = redact(result.text, result.findings, { style: result.policy.redactionStyle });

  out.innerHTML = `
    <div class="tester-verdict">
      <span class="tester-score" style="background:${result.risk.band.color}">${result.risk.score}</span>
      <span>${escapeHtml(result.verdict.headline)} — ${result.findings.length} finding(s), ${result.risk.band.label.toLowerCase()}</span>
    </div>
    <div class="tester-list">
      ${result.findings.map((f) => `
        <div class="tester-item" style="--cat:${CATEGORY_META[f.category].color}">
          <code>${escapeHtml(clip(f.value, 44))}</code> — ${escapeHtml(CATEGORY_META[f.category].short)} ·
          ${escapeHtml(f.title)} · ${f.severity} · ${(f.confidence * 100).toFixed(0)}%
        </div>`).join('') || '<div class="tester-item">Nothing sensitive found — this would send unchanged.</div>'}
    </div>
    <pre class="tester-out">${escapeHtml(redaction.text)}</pre>`;
}

function readFormSafe() {
  try { return readForm(); } catch { return policy; }
}

/* ------------------------------------------------------------------ */

async function renderAudit() {
  const s = summarise(await readAudit());
  $('#auditSummary').innerHTML = `
    <div class="stat"><strong>${s.scans}</strong><span>prompts checked</span></div>
    <div class="stat"><strong>${s.redacted}</strong><span>redacted before sending</span></div>
    <div class="stat"><strong>${s.overridden}</strong><span>sent as written</span></div>
    <div class="stat"><strong>${s.bySeverity.critical}</strong><span>critical items caught</span></div>`;
}

/* ------------------------------------------------------------------ */

function download(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function clip(s, n) {
  const one = String(s).replace(/\s+/g, ' ');
  return one.length > n ? `${one.slice(0, n)}…` : one;
}
