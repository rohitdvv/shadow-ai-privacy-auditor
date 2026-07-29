#!/usr/bin/env node
/**
 * Zero-dependency bundler for the browser extension.
 *
 * MV3 content scripts cannot be ES modules, so the shared engine is flattened
 * into a single classic script that exposes `globalThis.ShadowAI`. Because all
 * modules are authored in this repo we can do this with a deterministic
 * transform rather than a full bundler:
 *
 *   1. strip `import … from './x.js'` statements
 *   2. re-create any `X as Y` aliases as `const Y = X;`
 *   3. strip the `export ` keyword
 *   4. concatenate in dependency order inside one IIFE
 *
 * `engine/audit.js` is deliberately excluded: it uses localStorage, and a
 * content script shares localStorage with the host page. The extension keeps
 * its audit trail in chrome.storage.local instead.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const ORDER = [
  'constants.js',
  'validators.js',
  'gazetteers.js',
  'patterns.js',
  'ner.js',
  'context.js',
  'policy.js',
  'risk.js',
  'redact.js',
  'engine.js',
];

const EXPORTED = [
  'scan', 'redact', 'segment', 'scoreRisk', 'verdict',
  'CATEGORIES', 'CATEGORY_META', 'CATEGORY_LIST', 'SEVERITY', 'SEVERITY_RANK',
  'SEVERITY_WEIGHT', 'RISK_BANDS', 'bandForScore',
  'DEFAULT_POLICY', 'POLICY_PRESETS', 'normalisePolicy',
  'RULES', 'RULES_BY_ID', 'extractEntities',
];

const IMPORT_RE = /^[ \t]*import\s+[\s\S]*?from\s*['"][^'"]+['"];?[ \t]*$/gm;
const ALIAS_RE = /([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)/g;

/** Aliased imports (`CATEGORIES as C`) become one shared const at the top. */
const aliasMap = new Map();

function transform(filename) {
  const src = readFileSync(resolve(ROOT, 'engine', filename), 'utf8');

  let body = src.replace(IMPORT_RE, (stmt) => {
    const braces = stmt.match(/\{([\s\S]*?)\}/);
    if (braces) {
      let m;
      ALIAS_RE.lastIndex = 0;
      while ((m = ALIAS_RE.exec(braces[1])) !== null) {
        const [, source, local] = m;
        const existing = aliasMap.get(local);
        if (existing && existing !== source) {
          console.error(`✗ alias conflict: "${local}" maps to both ${existing} and ${source}`);
          process.exit(1);
        }
        aliasMap.set(local, source);
      }
    }
    return '';
  });

  body = body.replace(/^[ \t]*export\s+(?=(?:const|let|var|function|async function|class)\b)/gm, '');

  return `/* ==== engine/${filename} ==== */\n${body.trim()}\n`;
}

const banner = `/**
 * Shadow AI Privacy Auditor — bundled detection engine (generated file).
 *
 * DO NOT EDIT. Regenerate with: npm run build:extension
 * Source of truth: /engine/*.js
 *
 * Contains no network calls of any kind.
 */`;

const transformed = ORDER.map(transform);
const aliasBlock = `/* ==== import aliases ==== */\n${[...aliasMap].map(([local, source]) => `const ${local} = ${source};`).join('\n')}`;
const indent = (s) => s.split('\n').map((l) => (l ? `  ${l}` : l)).join('\n');

// Aliases all resolve to constants.js exports, so they are declared straight
// after it — `const` is in the temporal dead zone until then.
const constantsSrc = readFileSync(resolve(ROOT, 'engine/constants.js'), 'utf8');
for (const source of aliasMap.values()) {
  if (!new RegExp(`export\\s+const\\s+${source}\\b`).test(constantsSrc)) {
    console.error(`✗ alias source "${source}" is not exported from engine/constants.js`);
    process.exit(1);
  }
}

const modules = [transformed[0], aliasBlock, ...transformed.slice(1)].join('\n');

const bundle = `${banner}
(function (root) {
  'use strict';

${indent(modules)}

  root.ShadowAI = {
    version: '1.0.0',
${EXPORTED.map((name) => `    ${name}: typeof ${name} !== 'undefined' ? ${name} : undefined,`).join('\n')}
  };
})(typeof globalThis !== 'undefined' ? globalThis : self);
`;

mkdirSync(resolve(ROOT, 'extension/vendor'), { recursive: true });
writeFileSync(resolve(ROOT, 'extension/vendor/engine.bundle.js'), bundle, 'utf8');

const kb = (bundle.length / 1024).toFixed(1);
console.log(`✓ extension/vendor/engine.bundle.js  (${kb} kB, ${ORDER.length} modules)`);

/* Smoke-test the generated bundle in an isolated context. */
const { createContext, runInContext } = await import('node:vm');
const sandbox = { globalThis: {}, console };
sandbox.globalThis = sandbox;
createContext(sandbox);
runInContext(bundle, sandbox);
const api = sandbox.ShadowAI;
if (!api || typeof api.scan !== 'function') {
  console.error('✗ bundle did not expose ShadowAI.scan');
  process.exit(1);
}
const probe = api.scan('Contact Priya Raghavan on +1 (415) 555-0142 about the 3:00 PM meeting.');
const safe = api.scan('The project meeting is scheduled for 3:00 PM.');
if (probe.findings.length < 2 || safe.findings.length !== 0) {
  console.error('✗ bundle smoke test failed', {
    risky: probe.findings.map((f) => f.value),
    safe: safe.findings.map((f) => f.value),
  });
  process.exit(1);
}
console.log(`✓ bundle smoke test passed (risky: ${probe.findings.length} findings, safe: 0 findings)`);
