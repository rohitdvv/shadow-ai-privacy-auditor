/**
 * DEV-ONLY stub of the chrome.* extension APIs, so the real content script can
 * run inside a plain web page for previewing / screenshots. Never shipped.
 */
(function () {
  const store = { local: {}, sync: {} };
  const mkArea = (name) => ({
    get(keys, cb) {
      const out = {};
      const list = Array.isArray(keys) ? keys : keys ? [keys] : Object.keys(store[name]);
      for (const k of list) if (k in store[name]) out[k] = store[name][k];
      cb && cb(out);
    },
    set(obj, cb) { Object.assign(store[name], obj); cb && cb(); },
  });

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
      onChanged: { addListener() {} },
    },
  };
})();
