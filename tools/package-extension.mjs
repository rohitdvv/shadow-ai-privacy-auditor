#!/usr/bin/env node
/**
 * Package the extension into a Chrome Web Store-ready zip with manifest.json at
 * the top level. Writes dist/shadow-ai-privacy-auditor-extension.zip.
 *
 * Uses the system `zip` (present on macOS and Linux). On Windows, see the manual
 * step in docs/CHROME_WEB_STORE.md.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const EXT = resolve(ROOT, 'extension');
const OUT = resolve(ROOT, 'dist', 'shadow-ai-privacy-auditor-extension.zip');

if (!existsSync(resolve(EXT, 'vendor', 'engine.bundle.js'))) {
  console.error('✗ extension/vendor/engine.bundle.js missing — run `npm run build:extension` first.');
  process.exit(1);
}

mkdirSync(dirname(OUT), { recursive: true });
rmSync(OUT, { force: true });

try {
  execFileSync('zip', ['-r', '-q', OUT, '.', '-x', '*.DS_Store'], { cwd: EXT, stdio: 'inherit' });
} catch {
  console.error('✗ `zip` failed or is unavailable. See docs/CHROME_WEB_STORE.md for the manual step.');
  process.exit(1);
}

console.log(`✓ dist/shadow-ai-privacy-auditor-extension.zip`);
console.log('  Upload this at https://chrome.google.com/webstore/devconsole');
