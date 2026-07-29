#!/usr/bin/env node
/**
 * Generates the extension icon set as PNGs with no image library.
 *
 * The mark is a shield with a tick: drawn analytically with 4x supersampling,
 * then encoded as a minimal RGBA PNG (single IDAT, filter type 0).
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SIZES = [16, 32, 48, 128];

const NAVY = [31, 79, 216];
const WHITE = [255, 255, 255];

/* ----------------------------- geometry ----------------------------- */

function insideRoundedSquare(x, y, r) {
  const dx = Math.max(r - x, 0, x - (1 - r));
  const dy = Math.max(r - y, 0, y - (1 - r));
  return Math.hypot(dx, dy) <= r || (x >= 0 && x <= 1 && y >= 0 && y <= 1 && dx === 0 && dy === 0);
}

function insideShield(x, y) {
  if (y < 0.17 || y > 0.87) return false;
  const halfTop = 0.30;
  if (y <= 0.52) {
    const shoulder = y < 0.22 ? (y - 0.17) / 0.05 : 1;      // soften the top edge
    return Math.abs(x - 0.5) <= halfTop * (0.82 + 0.18 * shoulder);
  }
  const w = halfTop * ((0.87 - y) / 0.35) ** 0.72;
  return Math.abs(x - 0.5) <= w;
}

function distanceToSegment(px, py, ax, ay, bx, by) {
  const vx = bx - ax, vy = by - ay;
  const wx = px - ax, wy = py - ay;
  const len2 = vx * vx + vy * vy;
  const t = len2 ? Math.max(0, Math.min(1, (wx * vx + wy * vy) / len2)) : 0;
  return Math.hypot(px - (ax + t * vx), py - (ay + t * vy));
}

function insideTick(x, y) {
  const r = 0.052;
  return distanceToSegment(x, y, 0.375, 0.505, 0.462, 0.605) <= r
      || distanceToSegment(x, y, 0.462, 0.605, 0.655, 0.375) <= r;
}

/** Returns [r,g,b,a] for a point in the unit square. */
function sample(x, y) {
  if (!insideRoundedSquare(x, y, 0.22)) return [0, 0, 0, 0];
  if (insideShield(x, y)) {
    return insideTick(x, y) ? [...NAVY, 255] : [...WHITE, 255];
  }
  return [...NAVY, 255];
}

/* ------------------------------- render ------------------------------ */

function render(size) {
  const ss = 4;                       // supersampling factor
  const px = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const [sr, sg, sb, sa] = sample((x + (sx + 0.5) / ss) / size, (y + (sy + 0.5) / ss) / size);
          const alpha = sa / 255;
          r += sr * alpha; g += sg * alpha; b += sb * alpha; a += sa;
        }
      }
      const n = ss * ss;
      const alphaAvg = a / n;
      const norm = alphaAvg > 0 ? (a / 255) : 1;
      const i = (y * size + x) * 4;
      px[i]     = Math.round(r / norm);
      px[i + 1] = Math.round(g / norm);
      px[i + 2] = Math.round(b / norm);
      px[i + 3] = Math.round(alphaAvg);
    }
  }
  return px;
}

/* -------------------------------- PNG -------------------------------- */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, pixels) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;    // bit depth
  ihdr[9] = 6;    // colour type: RGBA
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0;   // filter: none
    pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/* -------------------------------- main ------------------------------- */

mkdirSync(resolve(ROOT, 'extension/icons'), { recursive: true });
for (const size of SIZES) {
  const png = encodePng(size, render(size));
  writeFileSync(resolve(ROOT, `extension/icons/icon${size}.png`), png);
  console.log(`✓ extension/icons/icon${size}.png  (${png.length} bytes)`);
}
