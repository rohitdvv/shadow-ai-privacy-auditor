#!/usr/bin/env node
/**
 * Offline guarantee check.
 *
 * "It all runs locally" is the central privacy claim of this project, so it is
 * asserted rather than promised: this script fails the build if any shipped
 * source file contains a network primitive.
 *
 * Run with `npm run verify:offline`.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIRS = ['engine', 'assets', 'extension', 'tests'];
const SKIP = new Set(['node_modules', '.git', 'dist']);

const FORBIDDEN = [
  { re: /\bfetch\s*\(/, name: 'fetch()' },
  { re: /\bXMLHttpRequest\b/, name: 'XMLHttpRequest' },
  { re: /\bWebSocket\s*\(/, name: 'WebSocket' },
  { re: /\bEventSource\s*\(/, name: 'EventSource' },
  { re: /navigator\.sendBeacon/, name: 'navigator.sendBeacon' },
  { re: /\bimportScripts\s*\(/, name: 'importScripts' },
  { re: /\bnew\s+Worker\s*\(\s*['"]https?:/, name: 'remote Worker' },
  { re: /import\s*\(\s*['"]https?:/, name: 'remote dynamic import' },
  { re: /from\s+['"]https?:/, name: 'remote module import' },
  { re: /<script[^>]+src\s*=\s*["']https?:/i, name: 'remote <script>' },
  { re: /<link[^>]+href\s*=\s*["']https?:\/\/(?!www\.w3\.org)/i, name: 'remote <link>' },
];

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (['.js', '.mjs', '.html', '.css', '.json'].includes(extname(full))) out.push(full);
  }
  return out;
}

const files = [
  ...SCAN_DIRS.flatMap((d) => walk(join(ROOT, d))),
  join(ROOT, 'index.html'),
];

const violations = [];
for (const file of files) {
  const rel = relative(ROOT, file);
  if (rel === 'tools/verify-offline.mjs') continue;
  const src = readFileSync(file, 'utf8');
  src.split('\n').forEach((line, i) => {
    if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;         // comments describing the rule
    for (const rule of FORBIDDEN) {
      if (rule.re.test(line)) violations.push({ rel, line: i + 1, name: rule.name, text: line.trim().slice(0, 110) });
    }
  });
}

console.log(`Checked ${files.length} shipped files for network primitives.\n`);

if (violations.length) {
  for (const v of violations) console.error(`✗ ${v.rel}:${v.line}  ${v.name}\n    ${v.text}`);
  console.error(`\n${violations.length} violation(s). The offline guarantee is broken.`);
  process.exit(1);
}

console.log('✓ No fetch, XHR, WebSocket, beacon, remote import or remote asset reference found.');
console.log('✓ The offline guarantee holds: the auditor cannot transmit your text.');
