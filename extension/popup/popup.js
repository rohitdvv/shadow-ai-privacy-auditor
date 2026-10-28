import { isEnabled, setEnabled, readAudit, clearAudit, summarise, getManaged } from '../shared/storage.js';

const CATEGORY_LABELS = {
  contact: ['Names & contact', '#2563eb'],
  government_financial: ['Gov / financial IDs', '#b91c1c'],
  credentials: ['Credentials', '#7c2d12'],
  medical_sensitive: ['Medical / sensitive', '#a21caf'],
  people_records: ['People records', '#0f766e'],
  org_confidential: ['Org confidential', '#a16207'],
};

const $ = (s) => document.querySelector(s);

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function render() {
  const managed = await getManaged();
  const enabled = managed.forceEnabled || await isEnabled();
  $('#enabled').checked = enabled;
  $('#enabled').disabled = managed.forceEnabled;
  $('#statusLine').textContent = managed.forceEnabled
    ? 'Always on — managed by your organisation'
    : enabled ? 'Monitoring active on AI chat sites' : 'Paused — nothing is being checked';

  const log = await readAudit();
  const s = summarise(log);

  $('#stats').innerHTML = `
    <div class="stat"><strong>${s.scans}</strong><span>prompts checked</span></div>
    <div class="stat"><strong>${s.redacted}</strong><span>redacted before sending</span></div>
    <div class="stat"><strong>${s.bySeverity.critical}</strong><span>critical items caught</span></div>
    <div class="stat"><strong>${s.last7Days}</strong><span>checks in the last 7 days</span></div>`;

  const entries = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 0;
  const bars = $('#categories');
  if (!entries.length) {
    bars.innerHTML = '<p class="empty">Nothing detected yet. Open ChatGPT, Gemini or Claude and start typing.</p>';
    return;
  }
  bars.innerHTML = entries.map(([cat, n]) => {
    const [label, colour] = CATEGORY_LABELS[cat] || [cat, '#5d6673'];
    const pct = max ? Math.round((n / max) * 100) : 0;
    return `<div class="bar-row"><span>${escapeHtml(label)}</span><span>${Number(n) || 0}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colour}"></div></div></div>`;
  }).join('');
}

$('#enabled').addEventListener('change', async (e) => {
  await setEnabled(e.target.checked);
  render();
});

$('#btnOptions').addEventListener('click', () => chrome.runtime.openOptionsPage());

$('#btnClear').addEventListener('click', async () => {
  await clearAudit();
  render();
});

render();
