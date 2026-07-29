/* global ShadowAI */
/**
 * Content script — real-time monitoring of AI chat composers.
 *
 * Flow:
 *   1. find the composer (textarea or contenteditable) on the page
 *   2. scan its contents locally, debounced, as the user types
 *   3. show a small status pill anchored to the composer
 *   4. intercept Enter / the send button when the risk score crosses the
 *      policy threshold, and offer a redacted version instead
 *
 * The script never transmits prompt text. The only thing it sends to the
 * extension's own service worker is a count-only audit entry.
 */

(() => {
  'use strict';

  if (window.__shadowAiAuditorLoaded) return;
  window.__shadowAiAuditorLoaded = true;

  const HOST = location.host;
  const DEBOUNCE_MS = 220;
  const BYPASS_MS = 2500;

  const state = {
    enabled: true,
    policy: ShadowAI.normalisePolicy(ShadowAI.DEFAULT_POLICY),
    composer: null,
    result: null,
    redaction: null,
    bypassUntil: 0,
    panelOpen: false,
    pendingSend: null,
  };

  /* ------------------------------------------------------------------ */
  /* config                                                              */
  /* ------------------------------------------------------------------ */

  /** Called at the very end of this file, once `ui` exists. */
  function loadConfig() {
    chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (cfg) => {
      if (chrome.runtime.lastError || !cfg) return;
      state.enabled = cfg.enabled !== false;
      state.policy = ShadowAI.normalisePolicy(cfg.policy || ShadowAI.DEFAULT_POLICY);
      rescan();
    });
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync') return;
    if (changes.policy) state.policy = ShadowAI.normalisePolicy(changes.policy.newValue || ShadowAI.DEFAULT_POLICY);
    if (changes.enabled) state.enabled = changes.enabled.newValue !== false;
    rescan();
  });

  /* ------------------------------------------------------------------ */
  /* composer discovery                                                  */
  /* ------------------------------------------------------------------ */

  const COMPOSER_SELECTORS = [
    '#prompt-textarea',                                  // ChatGPT
    'div.ProseMirror[contenteditable="true"]',           // ChatGPT / Claude
    'textarea[data-testid="chat-input"]',
    'rich-textarea div[contenteditable="true"]',         // Gemini
    'div[contenteditable="true"][role="textbox"]',       // generic
    'textarea[placeholder]',                             // Perplexity, Poe, HF Chat
    'textarea',
  ];

  function findComposer() {
    const active = document.activeElement;
    if (active && isComposer(active)) return active;
    for (const sel of COMPOSER_SELECTORS) {
      const nodes = [...document.querySelectorAll(sel)].filter(isVisible);
      if (nodes.length) return nodes[nodes.length - 1];
    }
    return null;
  }

  function isComposer(node) {
    if (!node || node.nodeType !== 1) return false;
    if (node.closest?.('#shadow-ai-auditor-root')) return false;
    const tag = node.tagName;
    if (tag === 'TEXTAREA') return isVisible(node);
    if (node.isContentEditable) return isVisible(node);
    return false;
  }

  function isVisible(node) {
    const rect = node.getBoundingClientRect?.();
    return !!rect && rect.width > 40 && rect.height > 10;
  }

  function readComposer(node) {
    if (!node) return '';
    if (node.tagName === 'TEXTAREA' || node.tagName === 'INPUT') return node.value || '';
    return node.innerText || node.textContent || '';
  }

  function writeComposer(node, text) {
    if (!node) return false;
    if (node.tagName === 'TEXTAREA' || node.tagName === 'INPUT') {
      const proto = node.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(node, text); else node.value = text;
      node.dispatchEvent(new Event('input', { bubbles: true }));
      node.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    }
    // contenteditable (ProseMirror, Quill, Lexical…): replace via the editor's
    // own input pipeline so its internal model stays in sync.
    node.focus();
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(node);
    selection.removeAllRanges();
    selection.addRange(range);
    const ok = document.execCommand('insertText', false, text);
    if (!ok) {
      node.textContent = text;
      node.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
    }
    return true;
  }

  /* ------------------------------------------------------------------ */
  /* scanning                                                            */
  /* ------------------------------------------------------------------ */

  let timer = null;
  function scheduleScan() {
    clearTimeout(timer);
    timer = setTimeout(rescan, DEBOUNCE_MS);
  }

  function rescan() {
    if (!state.enabled) { ui.hidePill(); return; }
    const composer = findComposer();
    state.composer = composer;
    const text = readComposer(composer);
    if (!text.trim()) {
      state.result = null;
      ui.hidePill();
      badge('safe', 0);
      return;
    }
    state.result = ShadowAI.scan(text, { policy: state.policy });
    state.redaction = ShadowAI.redact(state.result.text, state.result.findings, { style: state.policy.redactionStyle });
    ui.showPill(state.result, composer);
    badge(state.result.risk.band.level, state.result.findings.length);
    if (state.panelOpen) ui.renderPanel();
  }

  function badge(band, count) {
    try { chrome.runtime.sendMessage({ type: 'BADGE', band, count }); } catch { /* worker asleep */ }
  }

  function audit(action) {
    if (!state.result) return;
    try {
      chrome.runtime.sendMessage({
        type: 'AUDIT',
        entry: {
          score: state.result.risk.score,
          band: state.result.risk.band.level,
          counts: state.result.risk.counts,
          byCategory: state.result.risk.byCategory,
          totalFindings: state.result.findings.length,
          action,
          redactedCount: state.redaction?.replacements.length || 0,
          host: HOST,
        },
      });
    } catch { /* ignore */ }
  }

  document.addEventListener('input', (e) => { if (isComposer(e.target)) scheduleScan(); }, true);
  document.addEventListener('focusin', (e) => { if (isComposer(e.target)) scheduleScan(); }, true);
  window.addEventListener('resize', () => ui.reposition(), { passive: true });
  window.addEventListener('scroll', () => ui.reposition(), { passive: true });

  /* ------------------------------------------------------------------ */
  /* interception                                                        */
  /* ------------------------------------------------------------------ */

  const SEND_BUTTON_SELECTORS = [
    '[data-testid="send-button"]',
    'button[aria-label*="Send" i]',
    'button[aria-label*="Submit" i]',
    'button[type="submit"]',
    'button[data-testid="submit-button"]',
    'button.send-button',
  ];

  function shouldBlock() {
    if (!state.enabled || !state.result) return false;
    if (Date.now() < state.bypassUntil) return false;
    return state.result.risk.score >= state.policy.blockAtScore && state.result.findings.length > 0;
  }

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing) return;
    if (!isComposer(e.target)) return;
    // Make sure we are judging what is on screen right now, not a stale scan.
    if (!state.result || readComposer(e.target) !== state.result.text) {
      state.composer = e.target;
      const text = readComposer(e.target);
      if (text.trim()) {
        state.result = ShadowAI.scan(text, { policy: state.policy });
        state.redaction = ShadowAI.redact(state.result.text, state.result.findings, { style: state.policy.redactionStyle });
      }
    }
    if (!shouldBlock()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    state.pendingSend = { kind: 'enter', target: e.target };
    ui.openPanel();
  }, true);

  document.addEventListener('click', (e) => {
    const button = SEND_BUTTON_SELECTORS.map((s) => e.target.closest?.(s)).find(Boolean);
    if (!button) return;
    if (button.closest('#shadow-ai-auditor-root')) return;
    if (!state.composer) state.composer = findComposer();
    const text = readComposer(state.composer);
    if (text.trim() && (!state.result || state.result.text !== text)) {
      state.result = ShadowAI.scan(text, { policy: state.policy });
      state.redaction = ShadowAI.redact(state.result.text, state.result.findings, { style: state.policy.redactionStyle });
    }
    if (!shouldBlock()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    state.pendingSend = { kind: 'click', target: button };
    ui.openPanel();
  }, true);

  function resumeSend() {
    state.bypassUntil = Date.now() + BYPASS_MS;
    const pending = state.pendingSend;
    state.pendingSend = null;
    setTimeout(() => {
      if (pending?.kind === 'click' && document.contains(pending.target)) {
        pending.target.click();
        return;
      }
      const target = state.composer || findComposer();
      if (!target) return;
      const button = SEND_BUTTON_SELECTORS.map((s) => document.querySelector(s)).find((b) => b && !b.disabled);
      if (button) { button.click(); return; }
      target.focus();
      for (const type of ['keydown', 'keypress', 'keyup']) {
        target.dispatchEvent(new KeyboardEvent(type, {
          key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true,
        }));
      }
    }, 60);
  }

  /* ------------------------------------------------------------------ */
  /* UI (isolated in a shadow root so host page CSS cannot affect it)     */
  /* ------------------------------------------------------------------ */

  const ui = (() => {
    const host = document.createElement('div');
    host.id = 'shadow-ai-auditor-root';
    const root = host.attachShadow({ mode: 'open' });
    root.innerHTML = TEMPLATE();
    document.documentElement.append(host);

    const pill = root.getElementById('pill');
    const overlay = root.getElementById('overlay');
    const panel = root.getElementById('panel');

    pill.addEventListener('click', () => openPanel());

    root.getElementById('btnCancel').addEventListener('click', () => { audit('cancelled'); closePanel(); });
    overlay.addEventListener('click', (e) => { if (e.target === overlay) { audit('cancelled'); closePanel(); } });

    root.getElementById('btnRedact').addEventListener('click', () => {
      const redaction = ShadowAI.redact(state.result.text, state.result.findings, { style: state.policy.redactionStyle });
      writeComposer(state.composer, redaction.text);
      state.redaction = redaction;
      audit('redacted');
      closePanel();
      state.result = null;
      resumeSend();
    });

    root.getElementById('btnSendAnyway').addEventListener('click', () => {
      audit('sent-anyway');
      closePanel();
      resumeSend();
    });

    root.getElementById('btnCopyRedacted').addEventListener('click', async () => {
      const redaction = ShadowAI.redact(state.result.text, state.result.findings, { style: state.policy.redactionStyle });
      try { await navigator.clipboard.writeText(redaction.text); } catch { /* clipboard denied */ }
      const btn = root.getElementById('btnCopyRedacted');
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = 'Copy safe text'; }, 1600);
    });

    function showPill(result, composer) {
      const { risk } = result;
      pill.hidden = false;
      pill.dataset.band = risk.band.level;
      pill.querySelector('.pill-score').textContent = risk.score;
      pill.querySelector('.pill-text').textContent = result.findings.length === 0
        ? 'No sensitive data'
        : `${result.findings.length} item${result.findings.length === 1 ? '' : 's'} to review`;
      pill.title = `${risk.band.label} — ${risk.rationale.join(' ')}`;
      reposition(composer);
    }

    function hidePill() { pill.hidden = true; }

    function reposition(composer = state.composer) {
      if (pill.hidden) return;
      const rect = composer?.getBoundingClientRect?.();
      if (!rect || rect.width < 40) { pill.style.right = '18px'; pill.style.bottom = '18px'; pill.style.left = 'auto'; pill.style.top = 'auto'; return; }
      const top = Math.max(8, rect.top - 40);
      pill.style.top = `${top}px`;
      pill.style.left = `${Math.max(8, rect.right - 220)}px`;
      pill.style.right = 'auto';
      pill.style.bottom = 'auto';
    }

    function openPanel() {
      if (!state.result) return;
      state.panelOpen = true;
      overlay.hidden = false;
      renderPanel();
      root.getElementById('btnRedact').focus();
    }

    function closePanel() {
      state.panelOpen = false;
      overlay.hidden = true;
    }

    function renderPanel() {
      const { risk, findings } = state.result;
      panel.dataset.band = risk.band.level;
      root.getElementById('panelScore').textContent = risk.score;
      root.getElementById('panelHeadline').textContent = state.result.verdict.headline;
      root.getElementById('panelDetail').textContent = state.result.verdict.detail;
      root.getElementById('panelHost').textContent = HOST || 'this site';
      root.getElementById('panelSite').hidden = !HOST;

      const list = root.getElementById('list');
      list.replaceChildren();
      for (const f of findings) {
        const meta = ShadowAI.CATEGORY_META[f.category];
        const row = document.createElement('label');
        row.className = 'item';
        row.style.setProperty('--cat', meta.color);

        const box = document.createElement('input');
        box.type = 'checkbox';
        box.checked = f.redact;
        box.addEventListener('change', () => {
          f.redact = box.checked;
          state.redaction = ShadowAI.redact(state.result.text, state.result.findings, { style: state.policy.redactionStyle });
          root.getElementById('preview').textContent = state.redaction.text;
        });

        const body = document.createElement('div');
        body.innerHTML =
          `<div class="item-top"><code>${escapeHtml(clip(f.value, 46))}</code>` +
          `<span class="sev" data-sev="${f.severity}">${f.severity}</span></div>` +
          `<div class="item-cat">${escapeHtml(meta.short)} · ${escapeHtml(f.title)}</div>` +
          `<div class="item-why">${escapeHtml(f.why)}</div>`;

        row.append(box, body);
        list.append(row);
      }

      const redaction = ShadowAI.redact(state.result.text, findings, { style: state.policy.redactionStyle });
      root.getElementById('preview').textContent = redaction.text;
    }

    return { showPill, hidePill, reposition, openPanel, closePanel, renderPanel };
  })();

  function clip(s, n) {
    const one = String(s).replace(/\s+/g, ' ');
    return one.length > n ? `${one.slice(0, n)}…` : one;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Fetch the policy last: the callback calls rescan(), which needs `ui`.
  loadConfig();

  function TEMPLATE() {
    return `
<style>
  :host { all: initial; }
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }

  .pill {
    position: fixed; z-index: 2147483646;
    display: flex; align-items: center; gap: 8px;
    padding: 6px 12px 6px 8px; border-radius: 999px;
    background: #fff; color: #16191f;
    border: 1px solid #dfe3e9;
    box-shadow: 0 4px 16px rgba(16,24,40,.16);
    font-size: 12.5px; font-weight: 600; cursor: pointer;
    max-width: 240px;
  }
  .pill[hidden] { display: none; }
  .pill:hover { border-color: #b6bdc8; }
  .pill-score {
    display: grid; place-items: center;
    min-width: 24px; height: 24px; padding: 0 5px;
    border-radius: 999px; color: #fff; font-size: 11.5px; font-weight: 700;
    background: var(--band, #15803d);
  }
  .pill[data-band="safe"]      { --band: #15803d; }
  .pill[data-band="low"]       { --band: #65a30d; }
  .pill[data-band="moderate"]  { --band: #ca8a04; }
  .pill[data-band="high"]      { --band: #ea580c; }
  .pill[data-band="critical"]  { --band: #b91c1c; }
  .pill-text { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .overlay {
    position: fixed; inset: 0; z-index: 2147483647;
    background: rgba(9,12,17,.45);
    display: grid; place-items: center; padding: 20px;
  }
  .overlay[hidden] { display: none; }

  .panel {
    width: min(620px, 100%); max-height: min(84vh, 760px);
    display: flex; flex-direction: column;
    background: #fff; color: #16191f;
    border-radius: 14px; overflow: hidden;
    box-shadow: 0 24px 64px rgba(0,0,0,.35);
    border-top: 5px solid var(--band, #b91c1c);
  }
  .panel[data-band="moderate"] { --band: #ca8a04; }
  .panel[data-band="high"]     { --band: #ea580c; }
  .panel[data-band="critical"] { --band: #b91c1c; }

  .head { display: flex; gap: 14px; align-items: flex-start; padding: 16px 18px 12px; }
  .score {
    flex: 0 0 auto; display: grid; place-items: center;
    width: 52px; height: 52px; border-radius: 14px;
    background: var(--band, #b91c1c); color: #fff;
    font-size: 20px; font-weight: 700;
  }
  .head h2 { margin: 0; font-size: 16px; }
  .head p { margin: 3px 0 0; font-size: 13px; color: #5d6673; }
  .head .site { font-size: 11.5px; color: #5d6673; margin-top: 5px; }
  .head .site b { color: #16191f; }

  .list { overflow: auto; padding: 0 18px; display: flex; flex-direction: column; gap: 6px; max-height: 240px; }
  .item {
    display: grid; grid-template-columns: auto 1fr; gap: 10px; align-items: start;
    padding: 9px 10px; border: 1px solid #e6e9ee; border-left: 3px solid var(--cat, #888);
    border-radius: 8px; cursor: pointer; background: #fbfcfd;
  }
  .item:hover { background: #f4f6f9; }
  .item input { margin-top: 3px; accent-color: #1f4fd8; }
  .item-top { display: flex; align-items: center; gap: 8px; }
  .item-top code {
    font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; font-weight: 600;
    background: #eef1f5; border-radius: 4px; padding: 1px 5px; word-break: break-all;
  }
  .sev { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 1px 5px; border-radius: 4px; }
  .sev[data-sev="critical"] { background: #fee2e2; color: #b91c1c; }
  .sev[data-sev="high"]     { background: #ffedd5; color: #c2410c; }
  .sev[data-sev="medium"]   { background: #fef3c7; color: #a16207; }
  .sev[data-sev="low"]      { background: #ecfccb; color: #3f6212; }
  .item-cat { font-size: 11.5px; color: #5d6673; margin-top: 3px; }
  .item-why { font-size: 12px; color: #333a45; margin-top: 4px; line-height: 1.45; }

  .preview-wrap { padding: 12px 18px 0; }
  .preview-wrap h3 { margin: 0 0 5px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #5d6673; }
  .preview {
    margin: 0; padding: 10px 12px; border-radius: 8px; background: #f2f4f7; border: 1px solid #e6e9ee;
    font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.6;
    white-space: pre-wrap; word-break: break-word; max-height: 130px; overflow: auto;
  }

  .actions { display: flex; gap: 8px; padding: 14px 18px 16px; flex-wrap: wrap; }
  button {
    font: inherit; font-size: 13px; font-weight: 600;
    padding: 8px 14px; border-radius: 8px; cursor: pointer;
    border: 1px solid #c6ccd6; background: #fff; color: #16191f;
  }
  button:hover { background: #f2f4f7; }
  button.primary { background: #1f4fd8; border-color: #1f4fd8; color: #fff; }
  button.primary:hover { filter: brightness(1.08); }
  button.subtle { border-color: transparent; color: #5d6673; }
  button.spacer { margin-left: auto; }
  .note { padding: 0 18px 14px; font-size: 11.5px; color: #5d6673; }
</style>

<div class="pill" id="pill" hidden>
  <span class="pill-score">0</span>
  <span class="pill-text">Checking…</span>
</div>

<div class="overlay" id="overlay" hidden>
  <div class="panel" id="panel" role="dialog" aria-modal="true" aria-labelledby="panelHeadline">
    <div class="head">
      <div class="score" id="panelScore">0</div>
      <div>
        <h2 id="panelHeadline">Review before sending</h2>
        <p id="panelDetail"></p>
        <div class="site" id="panelSite">About to be sent to <b id="panelHost"></b></div>
      </div>
    </div>

    <div class="list" id="list"></div>

    <div class="preview-wrap">
      <h3>Safe version</h3>
      <pre class="preview" id="preview"></pre>
    </div>

    <div class="actions">
      <button class="primary" id="btnRedact">Redact and send</button>
      <button id="btnCopyRedacted">Copy safe text</button>
      <button class="subtle spacer" id="btnSendAnyway">Send as written</button>
      <button class="subtle" id="btnCancel">Cancel</button>
    </div>
    <p class="note">Analysed on your device. Nothing in this prompt has been uploaded or logged — the activity log records counts only.</p>
  </div>
</div>`;
  }
})();
