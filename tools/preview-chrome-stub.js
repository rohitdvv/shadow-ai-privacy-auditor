/**
 * DEV-ONLY stub of the chrome.* extension APIs, so the real content script can
 * run inside a plain web page for previewing / screenshots. Never shipped.
 */
(function () {
  const store = { local: {}, sync: {}, managed: {} };
  const mkArea = (name) => ({
    get(keys, cb) {
      const out = {};
      const list = Array.isArray(keys) ? keys : keys ? [keys] : Object.keys(store[name]);
      for (const k of list) if (k in store[name]) out[k] = store[name][k];
      cb && cb(out);
    },
    set(obj, cb) { Object.assign(store[name], obj); cb && cb(); },
  });

  // The content script uses a closed shadow root; it hands the root to this
  // object only when it exists (which it never does in a real isolated world).
  window.__SHADOW_AI_PREVIEW__ = {};

  window.chrome = {
    runtime: {
      lastError: undefined,
      sendMessage(msg, cb) {
        if (msg && msg.type === 'GET_CONFIG') { cb && cb({ enabled: true, policy: null }); return; }
        // BADGE / AUDIT messages: nothing to do in the preview.
        cb && cb(undefined);
      },
    },
    storage: {
      local: mkArea('local'),
      sync: mkArea('sync'),
      managed: mkArea('managed'),
      onChanged: { addListener() {} },
    },
  };
})();
