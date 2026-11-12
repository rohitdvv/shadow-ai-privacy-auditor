/**
 * Reversible redaction for the command line.
 *
 * `redactWithVault` swaps each sensitive value for a numbered placeholder and
 * records placeholder -> original in a "vault". `restore` puts the originals
 * back into text that came back from an AI assistant.
 *
 * Passing an existing vault keeps placeholders stable across a conversation:
 * the same person is [NAME_1] in every message, so the assistant's answers stay
 * coherent and one vault restores all of them.
 *
 * The vault holds the real values, so it never leaves this process except to
 * the file the user names. Nothing here touches a network.
 */

export const VAULT_VERSION = 1;

/** Same value, differently spaced or cased, gets the same placeholder. */
const normalise = (v) => String(v).trim().toLowerCase().replace(/\s+/g, ' ');

const PLACEHOLDER_RE = /^\[([A-Z][A-Z0-9_]*)_(\d+)\]$/;

export function emptyVault() {
  return { version: VAULT_VERSION, entries: {} };
}

/** Accept only well-formed vaults: a hostile file must not inject replacements. */
export function parseVault(json) {
  const raw = typeof json === 'string' ? JSON.parse(json) : json;
  if (!raw || typeof raw !== 'object' || raw.version !== VAULT_VERSION || !raw.entries || typeof raw.entries !== 'object') {
    throw new Error('not a shadow-ai vault file');
  }
  const vault = emptyVault();
  for (const [placeholder, value] of Object.entries(raw.entries)) {
    if (PLACEHOLDER_RE.test(placeholder) && typeof value === 'string' && value.length) {
      vault.entries[placeholder] = value;
    }
  }
  return vault;
}

/**
 * @param {string} text      original text
 * @param {Array}  findings  findings from scan()
 * @param {object} vault     existing vault to extend (not mutated)
 * @returns {{ text: string, vault: object, replaced: number }}
 */
export function redactWithVault(text, findings, vault = emptyVault()) {
  const entries = { ...vault.entries };
  const byValue = new Map();    // LABEL|normalised value -> placeholder
  const counters = new Map();   // LABEL -> highest index in use

  for (const [placeholder, value] of Object.entries(entries)) {
    const m = PLACEHOLDER_RE.exec(placeholder);
    if (!m) continue;
    byValue.set(`${m[1]}|${normalise(value)}`, placeholder);
    counters.set(m[1], Math.max(counters.get(m[1]) || 0, Number(m[2])));
  }

  const kept = findings
    .filter((f) => f.redact && !f.dismissed)
    .sort((a, b) => a.start - b.start);

  let out = '';
  let cursor = 0;
  let replaced = 0;

  for (const f of kept) {
    if (f.start < cursor) continue;                 // skip overlaps
    const original = text.slice(f.start, f.end);
    const key = `${f.label}|${normalise(original)}`;
    let placeholder = byValue.get(key);
    if (!placeholder) {
      const n = (counters.get(f.label) || 0) + 1;
      counters.set(f.label, n);
      placeholder = `[${f.label}_${n}]`;
      byValue.set(key, placeholder);
      entries[placeholder] = original;
    }
    out += text.slice(cursor, f.start) + placeholder;
    cursor = f.end;
    replaced++;
  }
  out += text.slice(cursor);

  return { text: out, vault: { version: VAULT_VERSION, entries }, replaced };
}

/**
 * Put original values back. Literal replacement only: no pattern in the vault
 * is ever compiled, and a restored value is never scanned for placeholders
 * again, so a value that happens to look like a placeholder cannot chain.
 *
 * @returns {{ text: string, restored: number, missing: string[] }}
 */
export function restore(text, vault) {
  const entries = vault.entries || {};
  let restored = 0;
  const missing = new Set();

  const out = String(text).replace(/\[[A-Z][A-Z0-9_]*_\d+\]/g, (placeholder) => {
    if (Object.prototype.hasOwnProperty.call(entries, placeholder)) {
      restored++;
      return entries[placeholder];
    }
    missing.add(placeholder);
    return placeholder;
  });

  return { text: out, restored, missing: [...missing] };
}
