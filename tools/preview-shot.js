/**
 * DEV-ONLY. Drives the preview harness into a specific state for headless
 * screenshots. Append ?shot=pill|welcome|panel|clean to the harness URL.
 * Never shipped.
 */
(function () {
  const shot = new URLSearchParams(location.search).get('shot');
  if (!shot) return;

  const PROMPT = 'Email John Carter at john.carter@acme.com, SSN 512-88-1044, and rotate the AWS key AKIA1234567890ABCD99.';
  const sr = () => {
    const root = document.getElementById('shadow-ai-auditor-root');
    return root && root.shadowRoot;
  };

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
