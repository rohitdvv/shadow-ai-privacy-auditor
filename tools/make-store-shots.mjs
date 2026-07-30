#!/usr/bin/env node
/**
 * Generate Chrome Web Store screenshots (1280×800) of the real extension UI.
 *
 * Spins up a tiny static server, then drives a headless Chrome/Chromium through
 * the preview harness (tools/extension-preview.html) in four states, saving PNGs
 * to dist/store-shots/. No third-party dependencies — uses the system browser.
 *
 * Override the browser with CHROME=/path/to/chrome npm run store:shots
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { mkdirSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = resolve(ROOT, 'dist', 'store-shots');
const PORT = 4319;

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };

const CANDIDATES = [
  process.env.CHROME,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
].filter(Boolean);

const chrome = CANDIDATES.find((p) => existsSync(p));
if (!chrome) {
  console.error('✗ No Chrome/Chromium found. Set CHROME=/path/to/chrome and retry.');
  process.exit(1);
}

const server = createServer(async (req, res) => {
  try {
    let pathname = decodeURIComponent(new URL(req.url, `http://localhost:${PORT}`).pathname);
    if (pathname.endsWith('/')) pathname += 'index.html';
    const target = join(ROOT, normalize(pathname));
    if (!target.startsWith(ROOT + sep)) { res.writeHead(403).end(); return; }
    const body = await readFile(target);
    res.writeHead(200, { 'Content-Type': TYPES[extname(target)] || 'application/octet-stream' }).end(body);
  } catch { res.writeHead(404).end('Not found'); }
});

await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
mkdirSync(OUT, { recursive: true });

const profile = resolve(ROOT, 'dist', '.chrome-profile');
mkdirSync(profile, { recursive: true });

const shots = ['pill', 'panel', 'clean', 'welcome'];
for (const shot of shots) {
  const out = join(OUT, `shot-${shot}.png`);
  try {
    execFileSync(chrome, [
      '--headless=new', '--disable-gpu', '--hide-scrollbars',
      '--no-first-run', '--no-default-browser-check',
      `--user-data-dir=${profile}`,
      '--force-device-scale-factor=1', '--window-size=1280,800',
      '--virtual-time-budget=2500', `--screenshot=${out}`,
      `http://localhost:${PORT}/tools/extension-preview.html?shot=${shot}`,
    ], { stdio: 'ignore', timeout: 60000 });
    console.log(existsSync(out) ? `✓ dist/store-shots/shot-${shot}.png` : `✗ shot-${shot} produced no file`);
  } catch (e) {
    console.error(`✗ shot-${shot} failed: ${e.message}`);
  }
}

rmSync(profile, { recursive: true, force: true });
server.close();
console.log('Done. Upload these as the store screenshots (1280×800).');
