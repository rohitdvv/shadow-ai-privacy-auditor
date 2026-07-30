/**
 * Service worker.
 *
 * Responsibilities:
 *   - hand the current policy to content scripts
 *   - keep the content-free audit log
 *   - drive the toolbar badge
 *
 * It never sees prompt text. Content scripts send counts, not content.
 */

import { getPolicy, isEnabled, appendAudit, readAudit, summarise } from './shared/storage.js';

const BADGE_COLOURS = {
  safe: '#15803d',
  low: '#65a30d',
  moderate: '#ca8a04',
  high: '#ea580c',
  critical: '#b91c1c',
};

chrome.runtime.onInstalled.addListener(async (details) => {
  // No policy is seeded: an absent policy means "use the engine defaults",
  // which keeps a fresh install identical to the published behaviour.
  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('options/options.html?welcome=1') });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message?.type) {
      case 'GET_CONFIG': {
        sendResponse({ policy: await getPolicy(), enabled: await isEnabled() });
        return;
      }
      case 'AUDIT': {
        await appendAudit({ ...message.entry, host: hostOf(sender) });
        sendResponse({ ok: true });
        return;
      }
      case 'BADGE': {
        const tabId = sender.tab?.id;
        if (tabId != null) {
          const { band, count } = message;
          await chrome.action.setBadgeText({ tabId, text: count ? String(count) : '' });
          await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLOURS[band] || '#5d6673' });
        }
        sendResponse({ ok: true });
        return;
      }
      case 'GET_SUMMARY': {
        sendResponse({ summary: summarise(await readAudit()) });
        return;
      }
      default:
        sendResponse({ ok: false, error: 'unknown message' });
    }
  })();
  return true; // keep the message channel open for the async response
});

function hostOf(sender) {
  try { return new URL(sender.tab?.url || sender.url).host; } catch { return null; }
}
