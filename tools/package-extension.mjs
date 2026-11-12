#!/usr/bin/env node
/**
 * Package the extension into a Chrome Web Store-ready zip with manifest.json at
 * the top level. Writes dist/shadow-ai-privacy-auditor-extension.zip.
 *
 * Uses the system `zip` (present on macOS and Linux). On Windows, see the manual
 * step in docs/CHROME_WEB_STORE.md.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync, existsSync, readFileSync, statSync, utimesSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
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

// Reproducible archive: the same source must give the same zip, byte for byte,
// so anyone can rebuild it and compare hashes. A zip records each file's
// timestamp, permissions and order, so all three are pinned here: files are
// staged with a fixed date and mode, listed in sorted order, and stored without
// platform-specific extra fields (-X) in UTC.
const FIXED_DATE = new Date('2020-01-01T00:00:00Z');
const stage = mkdtempSync(join(tmpdir(), 'shadow-ai-pack-'));
cpSync(EXT, stage, { recursive: true });

function walk(dir, out = []) {
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (entry === '.DS_Store') { rmSync(full); continue; }
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}
const files = walk(stage);
for (const file of files) {
  chmodSync(file, 0o644);
  utimesSync(file, FIXED_DATE, FIXED_DATE);
}
const list = files.map((f) => relative(stage, f).split('\\').join('/')).sort();

try {
  execFileSync('zip', ['-X', '-q', OUT, '-@'], {
    cwd: stage,
    input: `${list.join('\n')}\n`,
    env: { ...process.env, TZ: 'UTC' },
    stdio: ['pipe', 'inherit', 'inherit'],
  });
} catch {
  console.error('✗ `zip` failed or is unavailable. See docs/CHROME_WEB_STORE.md for the manual step.');
  process.exit(1);
} finally {
  rmSync(stage, { recursive: true, force: true });
}

// Publish a checksum alongside the zip so a download can be verified with
// `shasum -a 256 -c shadow-ai-privacy-auditor-extension.zip.sha256`.
const digest = createHash('sha256').update(readFileSync(OUT)).digest('hex');
writeFileSync(`${OUT}.sha256`, `${digest}  ${basename(OUT)}\n`);

console.log(`✓ dist/shadow-ai-privacy-auditor-extension.zip`);
console.log(`✓ dist/shadow-ai-privacy-auditor-extension.zip.sha256  (${digest.slice(0, 16)}…)`);
console.log('  Upload the zip at https://chrome.google.com/webstore/devconsole');
