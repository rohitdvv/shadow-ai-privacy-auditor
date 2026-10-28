/**
 * DEV-ONLY. Drives the preview harness into a specific state for headless
 * screenshots. Append ?shot=pill|welcome|panel|clean to the harness URL.
 * Never shipped.
 */
(function () {
  const shot = new URLSearchParams(location.search).get('shot');
  if (!shot) return;

  // Fictional values. Not acme.com: that is a known placeholder domain the
  // engine deliberately down-ranks, which would look like a miss in a screenshot.
  const PROMPT = 'Email John Carter at john.carter84@gmail.com, SSN 512-88-1044, and rotate the AWS key AKIA1234567890ABCD99.';
  // The extension's shadow root is closed; the dev stub receives it here.
  const sr = () => window.__SHADOW_AI_PREVIEW__ && window.__SHADOW_AI_PREVIEW__.root;

  window.addEventListener('load', () => {
    const c = document.getElementById('composer');
    c.textContent = PROMPT;
    c.dispatchEvent(new InputEvent('input', { bubbles: true }));

    setTimeout(() => {
      const s = sr();
      if (!s) return;
      const welcome = s.getElementById('welcome');
      welcome.hidden = shot !== 'welcome';
      if (shot === 'panel') s.getElementById('pill').click();
      if (shot === 'clean') s.getElementById('pillFix').click();
      document.documentElement.setAttribute('data-shot-ready', '1');
    }, 450);
  });
})();
