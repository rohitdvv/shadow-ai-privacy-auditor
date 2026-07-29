/**
 * Redaction.
 *
 * Design rules:
 *  - Only touch the exact character spans of kept findings. Everything else is
 *    byte-for-byte identical to the input. This is what guarantees that
 *    "The project meeting is scheduled for 3:00 PM" comes back unchanged.
 *  - Keep the text readable: the same person gets the same token every time,
 *    so an LLM can still follow "[NAME_1] emailed [NAME_2]".
 *  - Everything is reversible in the UI via per-finding keep/redact toggles.
 */

const PSEUDONYM_POOL = {
  NAME: ['Alex Rivera', 'Jordan Blake', 'Sam Okafor', 'Riley Nakamura', 'Casey Moreau', 'Devon Ashby'],
  EMAIL: ['a.rivera@example.com', 'j.blake@example.com', 's.okafor@example.com', 'r.nakamura@example.com'],
  PHONE: ['+1 555 0100', '+1 555 0101', '+1 555 0102', '+1 555 0103'],
  ORGANIZATION: ['Northwind Trading', 'Contoso Group', 'Acme Holdings', 'Globex Partners'],
  ADDRESS: ['1 Example Street, Springfield', '2 Sample Avenue, Springfield'],
};

/**
 * @param {string} text            original text
 * @param {Array}  findings        findings from scan()
 * @param {object} options
 *   style: 'label' | 'numbered' | 'mask' | 'pseudonym'
 * @returns {{ text, replacements, changed }}
 */
export function redact(text, findings, options = {}) {
  const style = options.style || 'numbered';
  const kept = findings
    .filter((f) => f.redact && !f.dismissed)
    .sort((a, b) => a.start - b.start);

  if (!kept.length) return { text, replacements: [], changed: false };

  const counters = new Map();      // label -> next index
  const assigned = new Map();      // label|value -> placeholder
  const replacements = [];

  let out = '';
  let cursor = 0;

  for (const f of kept) {
    if (f.start < cursor) continue;                    // defensive: skip overlaps
    const original = text.slice(f.start, f.end);
    const key = `${f.label}|${normalise(original)}`;

    let placeholder = assigned.get(key);
    if (!placeholder) {
      const n = (counters.get(f.label) || 0) + 1;
      counters.set(f.label, n);
      placeholder = buildPlaceholder(style, f.label, n, original);
      assigned.set(key, placeholder);
    }

    out += text.slice(cursor, f.start) + placeholder;
    cursor = f.end;
    replacements.push({
      id: f.id,
      label: f.label,
      category: f.category,
      severity: f.severity,
      placeholder,
      start: f.start,
      end: f.end,
      length: original.length,
    });
  }

  out += text.slice(cursor);
  return { text: out, replacements, changed: out !== text };
}

function normalise(v) {
  return String(v).trim().toLowerCase().replace(/\s+/g, ' ');
}

function buildPlaceholder(style, label, n, original) {
  switch (style) {
    case 'label':
      return `[${label}]`;
    case 'mask':
      return maskValue(original, label);
    case 'pseudonym': {
      const pool = PSEUDONYM_POOL[label];
      if (pool) return pool[(n - 1) % pool.length];
      return `[${label}_${n}]`;
    }
    case 'numbered':
    default:
      return `[${label}_${n}]`;
  }
}

/** Partial mask that preserves shape but not content. */
function maskValue(v, label) {
  if (label === 'EMAIL') {
    const [local, domain = ''] = v.split('@');
    const tld = domain.includes('.') ? domain.slice(domain.lastIndexOf('.')) : '';
    return `${local.slice(0, 1)}${'•'.repeat(Math.max(2, local.length - 1))}@${'•'.repeat(3)}${tld}`;
  }
  const digits = v.replace(/\D/g, '');
  if (digits.length >= 6) {
    const tail = digits.slice(-4);
    return `${'•'.repeat(Math.max(4, digits.length - 4))}${tail}`;
  }
  if (v.length <= 3) return '•'.repeat(v.length);
  return `${v.slice(0, 1)}${'•'.repeat(v.length - 2)}${v.slice(-1)}`;
}

/**
 * Build highlight segments for rendering: an ordered list of
 * { text, finding|null } covering the whole input exactly once.
 */
export function segment(text, findings) {
  const active = findings.filter((f) => !f.dismissed).sort((a, b) => a.start - b.start);
  const segments = [];
  let cursor = 0;
  for (const f of active) {
    if (f.start < cursor) continue;
    if (f.start > cursor) segments.push({ text: text.slice(cursor, f.start), finding: null });
    segments.push({ text: text.slice(f.start, f.end), finding: f });
    cursor = f.end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor), finding: null });
  return segments;
}
