/**
 * Context scoring, safe-span protection and overlap resolution.
 *
 * This module exists to stop over-redaction. Precision matters as much as
 * recall here: a tool that redacts "3:00 PM" trains users to ignore it.
 */

import { SEVERITY_RANK } from './constants.js';
import { CATEGORY_CONTEXT_CUES, CONTEXT_WINDOW } from './patterns.js';
import { PLACEHOLDER_CUES } from './gazetteers.js';

/**
 * Spans that are structurally safe and must never be reported on their own.
 * Any candidate finding fully contained in one of these is dropped.
 */
const SAFE_SPAN_PATTERNS = [
  // clock times: 3:00 PM, 15:30, 9 am, 3.00pm
  /\b\d{1,2}[:.]\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?\b/gi,
  /\b\d{1,2}\s*(?:[ap]\.?m\.?)\b/gi,
  // ISO and written dates without a birth-date cue
  /\b(?:19|20)\d{2}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g,
  /\b(?:Mon|Tue|Tues|Wed|Thu|Thur|Thurs|Fri|Sat|Sun)(?:day)?,?\s+\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\b/gi,
  /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?(?:,\s*\d{4})?\b/gi,
  // durations & quantities
  /\b\d+(?:\.\d+)?\s*(?:%|percent|pts?|points?|hours?|hrs?|minutes?|mins?|seconds?|secs?|days?|weeks?|months?|years?|people|users?|items?|rows?|records?|attendees?|participants?)\b/gi,
  // version numbers, ports, ranges
  /\bv?\d+\.\d+(?:\.\d+)*(?:-[A-Za-z0-9.]+)?\b/g,
  /\b(?:port|version|release|build|revision|rev)\s*[:#]?\s*\d+\b/gi,
  // measurement / file sizes
  /\b\d+(?:\.\d+)?\s*(?:kb|mb|gb|tb|ms|kg|lbs?|km|mi|cm|mm|px|em|rem)\b/gi,
  // ordinary rounded currency in a non-contract sentence is handled by rules; protect page/figure refs
  /\b(?:figure|fig\.|table|section|chapter|page|slide|item|step|question|q)\s*\.?\s*\d+(?:\.\d+)?\b/gi,
  // already-redacted placeholders
  /\[[A-Z_]{2,40}(?:_\d+)?\]/g,
  /<[A-Z_]{2,40}>/g,
  /\{\{[^}]{1,40}\}\}/g,
  /(?:x{4,}|\*{4,}|•{4,}|#{4,})/gi,
];

export function computeSafeSpans(text) {
  const spans = [];
  for (const re of SAFE_SPAN_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      spans.push([m.index, m.index + m[0].length]);
    }
  }
  return mergeSpans(spans);
}

function mergeSpans(spans) {
  if (!spans.length) return [];
  spans.sort((a, b) => a[0] - b[0]);
  const out = [spans[0].slice()];
  for (let i = 1; i < spans.length; i++) {
    const last = out[out.length - 1];
    if (spans[i][0] <= last[1]) last[1] = Math.max(last[1], spans[i][1]);
    else out.push(spans[i].slice());
  }
  return out;
}

export function isInsideSafeSpan(safeSpans, start, end) {
  return safeSpans.some(([s, e]) => start >= s && end <= e);
}

/** Cheap binary search free containment test for large inputs. */
export function overlapsSafeSpan(safeSpans, start, end) {
  return safeSpans.some(([s, e]) => start < e && end > s);
}

/**
 * Adjust a finding's confidence based on the words around it.
 * Returns { confidence, signals[] }.
 */
export function scoreContext(finding, text) {
  const from = Math.max(0, finding.start - CONTEXT_WINDOW);
  const to = Math.min(text.length, finding.end + CONTEXT_WINDOW);
  const ctx = text.slice(from, to).toLowerCase();
  const signals = [...(finding.signals || [])];
  let confidence = finding.confidence;

  const cues = CATEGORY_CONTEXT_CUES[finding.category] || [];
  const hits = cues.filter((c) => ctx.includes(c.toLowerCase()));
  if (hits.length) {
    confidence += Math.min(0.15, 0.05 * hits.length);
    signals.push(`supporting context: ${hits.slice(0, 3).join(', ')}`);
  }

  const placeholderHit = PLACEHOLDER_CUES.find((p) => ctx.includes(p));
  if (placeholderHit) {
    // A vendor-prefixed key or checksum-valid identifier stays confident even in
    // a page full of "example" text — it is still a real, usable value.
    const penalty = finding.strongIdentifier ? 0.05 : 0.22;
    confidence -= penalty;
    if (!finding.strongIdentifier) {
      signals.push(`looks illustrative ("${placeholderHit}")`);
      finding.illustrative = true;
    }
  }

  // Instructional / negated usage: "never paste your API key", "do not share the SSN"
  if (/\b(?:never|do not|don't|avoid|shouldn't|should not|must not|stop) (?:share|paste|send|post|include|store|commit|expose|reveal)\b/.test(ctx)) {
    confidence -= 0.2;
    signals.push('appears inside guidance about not sharing data');
  }

  // Question about the concept rather than a disclosure: "what is an IBAN?"
  if (/\b(?:what (?:is|are)|how (?:do|does|can) i|explain|definition of|difference between)\b/.test(ctx.slice(0, 90))) {
    confidence -= 0.12;
    signals.push('phrased as a general question');
  }

  finding.confidence = Math.max(0.05, Math.min(0.99, confidence));
  finding.signals = signals;
  return finding;
}

/**
 * Resolve overlapping findings. Priority order:
 *   1. higher severity
 *   2. longer span (a full IBAN beats a phone-shaped fragment inside it)
 *   3. higher confidence
 */
export function resolveOverlaps(findings) {
  const sorted = [...findings].sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev) return sev;
    const len = (b.end - b.start) - (a.end - a.start);
    if (len) return len;
    return b.confidence - a.confidence;
  });

  const kept = [];
  for (const f of sorted) {
    const clash = kept.some((k) => f.start < k.end && f.end > k.start);
    if (!clash) kept.push(f);
  }
  return kept.sort((a, b) => a.start - b.start);
}
